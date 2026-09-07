package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

type logMode int

const (
	logNone logMode = iota
	logBlocked
	logAll
)

// config is the fully resolved runtime configuration, assembled from the
// environment and the command line.
type config struct {
	Listen   string // unix socket QEMU connects to
	Upstream string // unix socket passt listens on

	Gateway   netip.Addr
	Guest     netip.Addr
	Resolvers []netip.Addr

	Strict    bool
	Stateful  bool
	FlowCap   int
	Reject    bool
	LogMode   logMode
	HTTPAddr  string
	RulesFile string
	Resolve   time.Duration

	// Rendered description of what was configured, printed at startup.
	Summary []string
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// truthy follows the same Y/N convention as the surrounding qemu image scripts.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "y", "yes", "1", "true", "on", "enable", "enabled":
		return true
	}
	return false
}

func falsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "n", "no", "0", "false", "off", "disable", "disabled":
		return true
	}
	return false
}

func parseLogMode(v string) logMode {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "none", "off", "n", "no", "0", "false":
		return logNone
	case "all", "verbose", "debug":
		return logAll
	default:
		return logBlocked
	}
}

// readResolvers extracts nameserver addresses from a resolv.conf-style file.
func readResolvers(path string) []netip.Addr {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(fields[1])); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// preset expands NET_PRESET into rule tokens applied before the user's own
// rules. It returns the tokens plus the fallback policy the preset implies.
func presetRules(name string) (tokens []string, fallback string, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "open", "none", "off":
		return nil, "", nil
	case "internet", "internet-only", "no-lan", "wan":
		// Everything except the container's neighbours and the host LAN.
		return []string{"deny:private", "deny:metadata"}, "allow", nil
	case "lan", "lan-only", "no-internet", "local":
		return []string{"allow:private"}, "deny", nil
	case "isolated", "none-at-all", "airgap", "airgapped":
		// Only the built-in DHCP/DNS essentials survive.
		return nil, "deny", nil
	default:
		return nil, "", fmt.Errorf("unknown NET_PRESET %q (open, internet, lan, isolated)", name)
	}
}

// buildRules assembles the egress and ingress ACLs from the environment.
//
// Evaluation order for a packet is:
//  1. built-in essentials (DHCP/DNS/NDP) unless NET_GUARD_STRICT=Y
//  2. NET_RULES, in the order written (verbs allowed per token)
//  3. NET_DENY
//  4. NET_ALLOW
//  5. NET_POLICY, defaulting to deny when NET_ALLOW is used and allow otherwise
func buildRules(cfg *config, env func(string) string) (out, in *ruleSet, err error) {
	ctx := aliasContext{gateway: cfg.Gateway, guest: cfg.Guest, resolver: cfg.Resolvers}

	presetTokens, presetPolicy, err := presetRules(env("NET_PRESET"))
	if err != nil {
		return nil, nil, err
	}

	fileRules, err := readRulesFile(cfg.RulesFile)
	if err != nil {
		return nil, nil, err
	}

	b := &builder{ctx: ctx}
	b.addOrdered(actionDeny, presetTokens...)

	if truthy(env("NET_BLOCK_PRIVATE")) {
		b.add(actionDeny, "private")
	}

	b.addOrdered(actionAllow, fileRules...)
	b.addOrdered(actionAllow, splitList(env("NET_RULES"))...)

	denyTokens := splitList(env("NET_DENY"))
	allowTokens := splitList(env("NET_ALLOW"))
	b.add(actionDeny, denyTokens...)
	b.add(actionAllow, allowTokens...)

	if e := b.err(); e != nil {
		return nil, nil, e
	}

	policy := env("NET_POLICY")
	if policy == "" {
		policy = presetPolicy
	}
	fallback := actionAllow
	implicit := false
	switch {
	case policy != "":
		a, ok := parseAction(policy)
		if !ok {
			return nil, nil, fmt.Errorf("invalid NET_POLICY %q (allow or deny)", policy)
		}
		fallback = a
	case len(allowTokens) > 0:
		// Listing what may be reached implies everything else may not.
		fallback = actionDeny
		implicit = true
	}
	out = &ruleSet{rules: b.rules, fallback: fallback, implicit: implicit}

	bi := &builder{ctx: ctx}
	denyIn := splitList(env("NET_DENY_IN"))
	allowIn := splitList(env("NET_ALLOW_IN"))
	bi.addOrdered(actionAllow, splitList(env("NET_RULES_IN"))...)
	bi.add(actionDeny, denyIn...)
	bi.add(actionAllow, allowIn...)
	if e := bi.err(); e != nil {
		return nil, nil, e
	}

	inFallback := actionAllow
	inImplicit := false
	if p := env("NET_POLICY_IN"); p != "" {
		a, ok := parseAction(p)
		if !ok {
			return nil, nil, fmt.Errorf("invalid NET_POLICY_IN %q (allow or deny)", p)
		}
		inFallback = a
	} else if len(allowIn) > 0 {
		inFallback = actionDeny
		inImplicit = true
	}
	in = &ruleSet{rules: bi.rules, fallback: inFallback, implicit: inImplicit}

	return out, in, nil
}

// readRulesFile loads rules from a file, ignoring blank lines and # comments.
func readRulesFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var tokens []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A whole line may hold "allow tcp:1.2.3.4:443" with a space verb.
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if a, ok := parseAction(fields[0]); ok {
				verb := "allow:"
				if a == actionDeny {
					verb = "deny:"
				}
				for _, t := range fields[1:] {
					for _, tok := range splitList(t) {
						tokens = append(tokens, verb+tok)
					}
				}
				continue
			}
		}
		tokens = append(tokens, splitList(line)...)
	}
	return tokens, nil
}

// describe renders the effective configuration for the container log.
func describe(cfg *config, out, in *ruleSet) []string {
	var lines []string
	if cfg.Listen != "" || cfg.Upstream != "" {
		lines = append(lines, fmt.Sprintf("socket: %s -> %s", cfg.Listen, cfg.Upstream))
	}
	if cfg.Gateway.IsValid() || cfg.Guest.IsValid() {
		lines = append(lines, fmt.Sprintf("guest: %s   gateway: %s", addrOrDash(cfg.Guest), addrOrDash(cfg.Gateway)))
	}

	lines = append(lines, "egress rules (guest -> network), first match wins:")
	lines = append(lines, renderRules(out)...)
	if len(in.rules) > 0 || in.fallback != actionAllow {
		lines = append(lines, "ingress rules (network -> guest), first match wins:")
		lines = append(lines, renderRules(in)...)
	}

	opts := []string{}
	if cfg.Strict {
		opts = append(opts, "strict (no built-in DHCP/DNS/NDP allowance)")
	} else {
		opts = append(opts, "DHCP/DNS/NDP always allowed")
	}
	if cfg.Stateful {
		opts = append(opts, "replies on established flows allowed")
	} else {
		opts = append(opts, "stateless (every packet matched on its own)")
	}
	if cfg.Reject {
		opts = append(opts, "reject blocked flows (TCP RST / ICMP prohibited)")
	} else {
		opts = append(opts, "silently drop blocked flows")
	}
	lines = append(lines, "options: "+strings.Join(opts, ", "))
	return lines
}

func renderRules(rs *ruleSet) []string {
	var lines []string
	for i, r := range rs.rules {
		lines = append(lines, fmt.Sprintf("  %2d. %s", i+1, r))
	}
	suffix := ""
	if rs.implicit {
		suffix = " (implied by NET_ALLOW)"
	}
	lines = append(lines, fmt.Sprintf("  ->  default: %s%s", rs.fallback, suffix))
	return lines
}

func addrOrDash(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}
