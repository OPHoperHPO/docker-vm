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
	if !p.ip {
		// ARP and other L2 control traffic is what makes the link usable at
		// all; the ACL operates on IP.
		return verdict{act: actionAllow, reason: "non-ip"}
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

// essential allows the handful of flows without which the guest cannot obtain
// an address or resolve names. Disabled by NET_GUARD_STRICT=Y.
func (f *filter) essential(p *packet, dir direction) (string, bool) {
	// DHCP / DHCPv6 to the passt-provided server.
	if p.proto == protoUDP && p.hasPorts {
		switch {
		case p.dstPort == 67 || p.dstPort == 68 || p.srcPort == 67 || p.srcPort == 68:
			return "dhcp", true
		case p.dstPort == 546 || p.dstPort == 547:
			return "dhcpv6", true
		}
	}

	// DNS towards the gateway address passt hands out, plus the container's
	// own resolvers when the guest was told to use them directly.
	if (p.proto == protoUDP || p.proto == protoTCP) && p.hasPorts {
		peer := p.dst
		if dir == ingress {
			peer = p.src
		}
		port := p.dstPort
		if dir == ingress {
			port = p.srcPort
		}
		if port == 53 && f.isResolver(peer) {
			return "dns", true
		}
	}

	// IPv6 neighbour discovery and multicast listener discovery.
	if p.proto == protoICMPv6 && p.l4Off < len(p.frame) {
		switch p.frame[p.l4Off] {
		case 130, 131, 132, 133, 134, 135, 136, 143:
			return "ndp", true
		}
	}

	return "", false
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
