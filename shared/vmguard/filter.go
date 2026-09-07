package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// direction of a frame relative to the guest.
type direction int

const (
	egress  direction = iota // guest -> outside world
	ingress                  // outside world -> guest
)

func (d direction) String() string {
	if d == ingress {
		return "in"
	}
	return "out"
}

type verdict struct {
	act    action
	rule   *rule
	reason string
}

// filter applies the configured ACLs to decoded frames and records statistics.
// The rule sets are swapped atomically so NET_RULES_FILE can be reloaded while
// the guest keeps running.
type filter struct {
	cfg *config

	out atomic.Pointer[ruleSet]
	in  atomic.Pointer[ruleSet]

	flows *conntrack

	stats  stats
	blocks blockLog
}

type stats struct {
	framesOut  atomic.Uint64
	framesIn   atomic.Uint64
	bytesOut   atomic.Uint64
	bytesIn    atomic.Uint64
	deniedOut  atomic.Uint64
	deniedIn   atomic.Uint64
	rejectsTCP atomic.Uint64
	rejectsICM atomic.Uint64
}

// blockEntry is one deduplicated blocked flow, kept for the status endpoint and
// for rate-limited logging.
type blockEntry struct {
	Direction string    `json:"direction"`
	Proto     string    `json:"proto"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Port      uint16    `json:"port,omitempty"`
	Rule      string    `json:"rule"`
	Count     uint64    `json:"count"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
}

type blockLog struct {
	mu      sync.Mutex
	entries map[string]*blockEntry
	order   []string
	limit   int
}

func (b *blockLog) record(key string, mk func() *blockEntry, now time.Time) (*blockEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.entries == nil {
		b.entries = make(map[string]*blockEntry)
		if b.limit == 0 {
			b.limit = 256
		}
	}
	if e, ok := b.entries[key]; ok {
		e.Count++
		e.Last = now
		return e, false
	}
	e := mk()
	e.Count = 1
	e.First, e.Last = now, now
	b.entries[key] = e
	b.order = append(b.order, key)
	if len(b.order) > b.limit {
		delete(b.entries, b.order[0])
		b.order = b.order[1:]
	}
	return e, true
}

func (b *blockLog) snapshot() []blockEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]blockEntry, 0, len(b.order))
	for _, k := range b.order {
		if e, ok := b.entries[k]; ok {
			out = append(out, *e)
		}
	}
	return out
}

func newFilter(cfg *config, out, in *ruleSet) *filter {
	f := &filter{cfg: cfg}
	if cfg.Stateful {
		f.flows = newConntrack(cfg.FlowCap)
	}
	f.setRules(out, in)
	return f
}

// setRules installs a new pair of ACLs; in-flight packets keep using the
// previous pair, which is what makes a live reload safe. Tracked flows are
// dropped so a tightened policy applies to connections that are already open.
func (f *filter) setRules(out, in *ruleSet) {
	f.out.Store(out)
	f.in.Store(in)
	if f.flows != nil {
		f.flows.reset()
	}
}

func (f *filter) rules() (out, in *ruleSet) { return f.out.Load(), f.in.Load() }

// trackedFlows reports the size of the connection table for the status page.
func (f *filter) trackedFlows() int {
	if f.flows == nil {
		return 0
	}
	return f.flows.size()
}

// inspect returns the verdict for one decoded frame.
func (f *filter) inspect(p *packet, dir direction) verdict {

	// What vmguard could not read, it must not forward. passt dispatches on the
	// ethertype and is far more forgiving about the headers behind it, so a
	// frame this decoder gives up on is not "harmless non-IP traffic" — it is a
	// packet passt may well deliver to the very destination the rules forbid.
	switch p.etherType {
	case ethTypeIPv4, ethTypeIPv6:
		if !p.ip || p.malformed {
			return verdict{act: actionDeny, reason: "undecodable"}
		}
	case ethTypeARP:
		// The link cannot come up without it, and it carries no L3 destination
		// for the ACL to judge.
		return verdict{act: actionAllow, reason: "arp"}
	default:
		// passt handles ARP, IPv4 and IPv6 and drops the rest, so denying here
		// costs nothing and keeps "undecidable means denied" true of every
		// frame that reaches this point.
		return verdict{act: actionDeny, reason: "unknown-ethertype"}
	}

	// Refused before anything else: a rule that constrains ports cannot decide a
	// packet whose ports were deliberately left in a later fragment.
	if p.truncatedFirstFragment() {
		return verdict{act: actionDeny, reason: "truncated-fragment"}
	}

	if !f.cfg.Strict {
		if r, ok := f.essential(p, dir); ok {
			return verdict{act: actionAllow, reason: r}
		}
	}

	now := time.Now()
	var key flowKey
	if f.flows != nil {
		key = keyFor(p, dir)
		if tearsDown(p) {
			f.flows.forget(key)
		} else if f.flows.seen(key, now) {
			// Part of a conversation the rules already permitted.
			return verdict{act: actionAllow, reason: "established"}
		}
	}

	rs := f.out.Load()
	addr := p.dst
	if dir == ingress {
		rs = f.in.Load()
		addr = p.src
	}
	if rs == nil {
		return verdict{act: actionAllow, reason: "no-rules"}
	}

	act, rule := rs.decide(addr, p.protoName(), portOf(p, dir), p.hasPorts)
	v := verdict{act: act, rule: rule}
	if rule == nil {
		v.reason = "default-" + act.String()
	}

	if act == actionAllow && f.flows != nil && !tearsDown(p) {
		f.flows.record(key, now)
	}
	return v
}

// portOf picks the port rules match on. Both directions use the destination
// port: what the guest dialled on the way out, and the guest's own listening
// port on the way in.
func portOf(p *packet, _ direction) uint16 { return p.dstPort }

// broadcastV4 is the limited broadcast address a DHCP client uses before it
// has been given one of its own.
var broadcastV4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// essential allows the handful of flows without which the guest cannot obtain
// an address or resolve names. Disabled by NET_GUARD_STRICT=Y.
//
// Every field these exemptions look at is chosen by the guest, so each one is
// pinned down to the exact exchange it is meant to permit. An exemption written
// as "any packet on port 67 or 68" would be a way around the whole ACL: the
// guest would only have to pick that source port to reach any destination.
func (f *filter) essential(p *packet, dir direction) (string, bool) {

	if p.proto == protoUDP && p.hasPorts {
		if f.isDHCP(p, dir) {
			return "dhcp", true
		}
		if f.isDHCPv6(p, dir) {
			return "dhcpv6", true
		}
	}

	if (p.proto == protoUDP || p.proto == protoTCP) && p.hasPorts && f.isDNS(p, dir) {
		return "dns", true
	}

	if p.proto == protoICMPv6 && f.isNDP(p, dir) {
		return "ndp", true
	}

	return "", false
}

// isDHCP matches the DHCPv4 exchange with the server passt provides: the client
// sends from 68 to 67, the server answers from 67 to 68, and the peer is either
// the broadcast address or the gateway.
func (f *filter) isDHCP(p *packet, dir direction) bool {

	if !p.src.Is4() || !p.dst.Is4() {
		return false
	}

	if dir == egress {
		return p.srcPort == 68 && p.dstPort == 67 && f.isDHCPPeer(p.dst)
	}
	return p.srcPort == 67 && p.dstPort == 68 && f.isDHCPPeer(p.src)
}

// isDHCPPeer accepts the addresses a DHCPv4 conversation legitimately uses: the
// limited broadcast and the unspecified address before the lease exists, and
// the gateway once the client renews its lease by unicast.
func (f *filter) isDHCPPeer(a netip.Addr) bool {

	if !a.IsValid() {
		return false
	}
	if a == broadcastV4 || a.IsUnspecified() {
		return true
	}
	return f.cfg.Gateway.IsValid() && a == f.cfg.Gateway
}

// isDHCPv6 matches the DHCPv6 exchange, which runs between 546 and 547 and
// never leaves the link.
func (f *filter) isDHCPv6(p *packet, dir direction) bool {

	if !p.src.Is6() || !p.dst.Is6() {
		return false
	}

	if dir == egress {
		return p.srcPort == 546 && p.dstPort == 547 && f.isOnLink(p.dst)
	}
	return p.srcPort == 547 && p.dstPort == 546 && f.isOnLink(p.src)
}

// isNDP matches neighbour discovery and multicast listener discovery. Both are
// link-local by definition, so the same message type addressed to a routable
// address is ordinary traffic and gets no exemption.
func (f *filter) isNDP(p *packet, dir direction) bool {

	if p.l4Off <= 0 || p.l4Off >= len(p.frame) {
		return false
	}

	switch p.frame[p.l4Off] {
	case 130, 131, 132, 133, 134, 135, 136, 143:
	default:
		return false
	}

	peer := p.dst
	if dir == ingress {
		peer = p.src
	}
	return f.isOnLink(peer)
}

// isOnLink accepts the addresses link-local protocols may use: an IPv6
// multicast group, a link-local address, the unspecified address during
// duplicate address detection, or the gateway itself.
func (f *filter) isOnLink(a netip.Addr) bool {

	if !a.IsValid() || !a.Is6() {
		return false
	}
	if a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return true
	}
	return f.cfg.Gateway.IsValid() && a == f.cfg.Gateway
}

// isDNS matches name resolution towards the address passt hands out as the
// resolver, plus the container's own nameservers when the guest was pointed at
// them directly. Any other destination on port 53 is ordinary traffic.
func (f *filter) isDNS(p *packet, dir direction) bool {

	peer, port := p.dst, p.dstPort
	if dir == ingress {
		peer, port = p.src, p.srcPort
	}
	return port == 53 && f.isResolver(peer)
}

func (f *filter) isResolver(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if f.cfg.Gateway.IsValid() && a == f.cfg.Gateway {
		return true
	}
	for _, r := range f.cfg.Resolvers {
		if a == r {
			return true
		}
	}
	return false
}

// note updates counters and the deduplicated block log; it returns a line to log
// when this flow has not been reported recently.
func (f *filter) note(p *packet, dir direction, v verdict, now time.Time) string {
	if v.act != actionDeny {
		return ""
	}
	if dir == ingress {
		f.stats.deniedIn.Add(1)
	} else {
		f.stats.deniedOut.Add(1)
	}

	src, dst := p.src, p.dst
	port := p.dstPort
	key := fmt.Sprintf("%s|%s|%s|%d", dir, p.protoName(), dst, port)
	if dir == ingress {
		key = fmt.Sprintf("%s|%s|%s|%d", dir, p.protoName(), src, port)
	}

	ruleText := v.reason
	if v.rule != nil {
		ruleText = v.rule.String()
	}

	_, fresh := f.blocks.record(key, func() *blockEntry {
		return &blockEntry{
			Direction: dir.String(),
			Proto:     p.protoName(),
			Src:       src.String(),
			Dst:       dst.String(),
			Port:      port,
			Rule:      ruleText,
		}
	}, now)

	if !fresh || f.cfg.LogMode == logNone {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "blocked %s %s %s", dir, p.protoName(), src)
	if p.hasPorts {
		fmt.Fprintf(&b, ":%d", p.srcPort)
	}
	fmt.Fprintf(&b, " -> %s", dst)
	if p.hasPorts {
		fmt.Fprintf(&b, ":%d", p.dstPort)
	}
	fmt.Fprintf(&b, " (%s)", ruleText)
	return b.String()
}
