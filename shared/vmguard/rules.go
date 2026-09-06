package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type action uint8

const (
	actionAllow action = iota
	actionDeny
)

func (a action) String() string {
	if a == actionDeny {
		return "deny"
	}
	return "allow"
}

func parseAction(s string) (action, bool) {
	switch strings.ToLower(s) {
	case "allow", "accept", "permit":
		return actionAllow, true
	case "deny", "drop", "block", "reject":
		return actionDeny, true
	}
	return actionAllow, false
}

type portRange struct{ lo, hi uint16 }

func (p portRange) contains(v uint16) bool { return v >= p.lo && v <= p.hi }

func (p portRange) String() string {
	if p.lo == p.hi {
		return strconv.Itoa(int(p.lo))
	}
	return fmt.Sprintf("%d-%d", p.lo, p.hi)
}

// rule is one line of the ACL. An empty proto matches every protocol, empty
// ports match every port, and a non-empty host is re-resolved periodically.
type rule struct {
	act   action
	proto string // "", "tcp", "udp", "icmp"
	host  string // hostname rules only
	ports []portRange
	raw   string

	// nets is swapped atomically so DNS refreshes never block the data path.
	nets atomic.Pointer[[]netip.Prefix]
}

func (r *rule) prefixes() []netip.Prefix {
	if p := r.nets.Load(); p != nil {
		return *p
	}
	return nil
}

func (r *rule) setPrefixes(p []netip.Prefix) { r.nets.Store(&p) }

// matches reports whether the rule applies to addr/proto/port. hasPort is false
// for fragments and for protocols without ports, in which case a rule that
// constrains ports cannot match.
func (r *rule) matches(addr netip.Addr, proto string, port uint16, hasPort bool) bool {
	if r.proto != "" && r.proto != proto {
		return false
	}
	if len(r.ports) > 0 {
		if !hasPort {
			return false
		}
		ok := false
		for _, pr := range r.ports {
			if pr.contains(port) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, n := range r.prefixes() {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *rule) String() string {
	var b strings.Builder
	b.WriteString(r.act.String())
	b.WriteString(" ")
	if r.proto != "" {
		b.WriteString(r.proto)
		b.WriteString(":")
	}
	if r.host != "" {
		b.WriteString(r.host)
		nets := r.prefixes()
		if len(nets) > 0 {
			addrs := make([]string, 0, len(nets))
			for _, n := range nets {
				addrs = append(addrs, n.Addr().String())
			}
			b.WriteString("(" + strings.Join(addrs, ",") + ")")
		} else {
			b.WriteString("(unresolved)")
		}
	} else {
		nets := r.prefixes()
		parts := make([]string, 0, len(nets))
		for _, n := range nets {
			parts = append(parts, n.String())
		}
		b.WriteString(strings.Join(parts, ","))
	}
	if len(r.ports) > 0 {
		parts := make([]string, 0, len(r.ports))
		for _, p := range r.ports {
			parts = append(parts, p.String())
		}
		b.WriteString(":" + strings.Join(parts, ","))
	}
	return b.String()
}

// ruleSet is an ordered, first-match-wins ACL plus the fallback policy applied
// when no rule matches.
type ruleSet struct {
	rules    []*rule
	fallback action
	// implicit records that fallback was derived from the presence of allow
	// rules rather than set explicitly, for the startup summary.
	implicit bool
}

func (rs *ruleSet) decide(addr netip.Addr, proto string, port uint16, hasPort bool) (action, *rule) {
	for _, r := range rs.rules {
		if r.matches(addr, proto, port, hasPort) {
			return r.act, r
		}
	}
	return rs.fallback, nil
}

func (rs *ruleSet) hostRules() []*rule {
	var out []*rule
	for _, r := range rs.rules {
		if r.host != "" {
			out = append(out, r)
		}
	}
	return out
}

// aliasContext supplies the runtime addresses that symbolic targets expand to.
type aliasContext struct {
	gateway  netip.Addr   // passt gateway as seen by the guest
	guest    netip.Addr   // address assigned to the guest
	resolver []netip.Addr // nameservers from /etc/resolv.conf
}

var (
	privateNets = mustPrefixes(
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10",
	)
	rfc1918Nets   = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	loopbackNets  = mustPrefixes("127.0.0.0/8", "::1/128")
	linkLocalNets = mustPrefixes("169.254.0.0/16", "fe80::/10")
	metadataNets  = mustPrefixes("169.254.169.254/32", "fd00:ec2::254/128")
	multicastNets = mustPrefixes("224.0.0.0/4", "ff00::/8", "255.255.255.255/32")
	anyNets       = mustPrefixes("0.0.0.0/0", "::/0")
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, v := range s {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			panic("vmguard: bad builtin prefix " + v + ": " + err.Error())
		}
		out = append(out, p)
	}
	return out
}

func hostPrefixes(addrs ...netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

var numericToken = regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`)

// splitList accepts comma, semicolon, whitespace and newline separated lists so
// rules can be written inline in compose or one per line in a file.
//
// A comma also separates ports inside a single rule ("tcp:10.0.0.1:80,443"), so
// a fragment that is nothing but a port number is folded back into the rule it
// belongs to. No valid target is ever a bare number, which is what makes the
// rejoin unambiguous.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})

	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if numericToken.MatchString(f) && len(out) > 0 && hasPortSpec(out[len(out)-1]) {
			out[len(out)-1] += "," + f
			continue
		}
		out = append(out, f)
	}
	return out
}

// hasPortSpec reports whether a token already carries a ":ports" section.
func hasPortSpec(token string) bool {
	_, _, ports, err := splitToken(token)
	return err == nil && ports != ""
}

// splitToken separates the optional protocol keyword, the target and the
// optional port list. IPv6 literals must be bracketed when ports follow.
func splitToken(token string) (proto, target, ports string, err error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", "", fmt.Errorf("empty rule")
	}

	if i := strings.Index(token, ":"); i > 0 {
		if p, ok := protoKeywords[strings.ToLower(token[:i])]; ok {
			proto = p
			token = token[i+1:]
		}
	}
	if token == "" {
		return "", "", "", fmt.Errorf("no target")
	}

	target = token
	switch {
	case strings.HasPrefix(token, "["):
		end := strings.Index(token, "]")
		if end < 0 {
			return "", "", "", fmt.Errorf("unterminated '['")
		}
		target = token[1:end]
		rest := token[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", "", "", fmt.Errorf("unexpected %q after ']'", rest)
			}
			ports = rest[1:]
		}
	case strings.Count(token, ":") == 1:
		i := strings.Index(token, ":")
		target, ports = token[:i], token[i+1:]
	}
	return proto, target, ports, nil
}

var protoKeywords = map[string]string{
	"tcp":    "tcp",
	"udp":    "udp",
	"icmp":   "icmp",
	"icmpv6": "icmp",
	"ip":     "",
	"any":    "",
	"all":    "",
}

// parseRule turns one selector token into a rule. Accepted forms:
//
//	[proto:]target[:ports]
//	target             10.0.0.0/8 | 1.2.3.4 | fd00::/8 | example.com | alias
//	ports              80 | 80,443 | 8000-8100 | *
//
// IPv6 literals must be bracketed when ports follow: tcp:[2001:db8::/32]:443
func parseRule(act action, token string, ctx aliasContext) (*rule, error) {
	raw := strings.TrimSpace(token)

	proto, target, portSpec, err := splitToken(raw)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", raw, err)
	}

	r := &rule{act: act, proto: proto, raw: raw}

	if portSpec != "" && portSpec != "*" {
		ports, err := parsePorts(portSpec)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", raw, err)
		}
		r.ports = ports
	}

	nets, host, err := resolveTarget(target, ctx)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", raw, err)
	}
	r.host = host
	r.setPrefixes(nets)
	return r, nil
}

func parsePorts(spec string) ([]portRange, error) {
	var out []portRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.Index(part, "-"); i >= 0 {
			lo, hi = part[:i], part[i+1:]
		}
		l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		h, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if l > h {
			l, h = h, l
		}
		out = append(out, portRange{uint16(l), uint16(h)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports in %q", spec)
	}
	return out, nil
}

// resolveTarget expands an alias, parses a CIDR/address, or reports a hostname
// that the resolver loop will fill in later.
func resolveTarget(target string, ctx aliasContext) (nets []netip.Prefix, host string, err error) {
	switch strings.ToLower(target) {
	case "any", "all", "*", "internet":
		return anyNets, "", nil
	case "private", "lan":
		return privateNets, "", nil
	case "rfc1918":
		return rfc1918Nets, "", nil
	case "loopback", "localhost":
		return loopbackNets, "", nil
	case "link-local", "linklocal":
		return linkLocalNets, "", nil
	case "metadata":
		return metadataNets, "", nil
	case "multicast":
		return multicastNets, "", nil
	case "host", "gateway", "hostgw":
		return hostPrefixes(ctx.gateway), "", nil
	case "guest", "self":
		return hostPrefixes(ctx.guest), "", nil
	case "dns", "resolver":
		return hostPrefixes(ctx.resolver...), "", nil
	}

	if strings.Contains(target, "/") {
		p, perr := netip.ParsePrefix(target)
		if perr != nil {
			return nil, "", fmt.Errorf("invalid CIDR %q", target)
		}
		return []netip.Prefix{p.Masked()}, "", nil
	}

	if a, aerr := netip.ParseAddr(target); aerr == nil {
		return hostPrefixes(a.Unmap()), "", nil
	}

	if !looksLikeHostname(target) {
		return nil, "", fmt.Errorf("%q is not an address, CIDR, alias or hostname", target)
	}
	return nil, target, nil
}

func looksLikeHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' && i > 0 && i < len(label)-1:
			case c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// builder accumulates rules while keeping parse errors for a single report.
type builder struct {
	ctx   aliasContext
	rules []*rule
	errs  []string
}

func (b *builder) add(act action, tokens ...string) {
	for _, t := range tokens {
		r, err := parseRule(act, t, b.ctx)
		if err != nil {
			b.errs = append(b.errs, err.Error())
			continue
		}
		b.rules = append(b.rules, r)
	}
}

// addOrdered parses tokens that may carry their own verb, e.g. "deny:private"
// or "allow:tcp:0.0.0.0/0:443". Tokens without a verb take the default action.
func (b *builder) addOrdered(def action, tokens ...string) {
	for _, t := range tokens {
		act := def
		body := t
		if i := strings.Index(t, ":"); i > 0 {
			if a, ok := parseAction(t[:i]); ok {
				act, body = a, t[i+1:]
			}
		}
		b.add(act, body)
	}
}

func (b *builder) err() error {
	if len(b.errs) == 0 {
		return nil
	}
	sort.Strings(b.errs)
	return fmt.Errorf("%s", strings.Join(b.errs, "; "))
}

// hostResolver periodically re-resolves hostname rules. It is shared by the
// egress and ingress rule sets.
type hostResolver struct {
	mu      sync.Mutex
	lookup  func(string) ([]netip.Addr, error)
	targets []*rule
}

func (h *hostResolver) refresh() {
	h.mu.Lock()
	targets := append([]*rule(nil), h.targets...)
	lookup := h.lookup
	h.mu.Unlock()

	for _, r := range targets {
		addrs, err := lookup(r.host)
		if err != nil || len(addrs) == 0 {
			// Keep the previous answer: a transient resolver failure must not
			// silently widen or narrow the ACL.
			continue
		}
		r.setPrefixes(hostPrefixes(addrs...))
	}
}
