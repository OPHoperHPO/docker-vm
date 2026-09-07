package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRuleForms(t *testing.T) {
	ctx := aliasContext{
		gateway:  netip.MustParseAddr("20.20.20.1"),
		guest:    netip.MustParseAddr("20.20.20.21"),
		resolver: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	}

	tests := []struct {
		token     string
		proto     string
		nets      []string
		ports     []portRange
		host      string
		wantError bool
	}{
		{token: "10.0.0.0/8", nets: []string{"10.0.0.0/8"}},
		{token: "1.2.3.4", nets: []string{"1.2.3.4/32"}},
		{token: "tcp:1.2.3.4", proto: "tcp", nets: []string{"1.2.3.4/32"}},
		{token: "tcp:1.2.3.4:443", proto: "tcp", nets: []string{"1.2.3.4/32"}, ports: []portRange{{443, 443}}},
		{token: "udp:*:53", proto: "udp", nets: []string{"0.0.0.0/0", "::/0"}, ports: []portRange{{53, 53}}},
		{token: "any:10.0.0.0/8:80,443", nets: []string{"10.0.0.0/8"}, ports: []portRange{{80, 80}, {443, 443}}},
		{token: "tcp:0.0.0.0/0:8000-8100", proto: "tcp", nets: []string{"0.0.0.0/0"}, ports: []portRange{{8000, 8100}}},
		{token: "2001:db8::/32", nets: []string{"2001:db8::/32"}},
		{token: "tcp:[2001:db8::/32]:443", proto: "tcp", nets: []string{"2001:db8::/32"}, ports: []portRange{{443, 443}}},
		{token: "[fd00::1]", nets: []string{"fd00::1/128"}},
		{token: "icmp:private", proto: "icmp", nets: []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
			"::1/128", "fc00::/7", "fe80::/10",
		}},
		{token: "gateway", nets: []string{"20.20.20.1/32"}},
		{token: "dns", nets: []string{"1.1.1.1/32"}},
		{token: "metadata", nets: []string{"169.254.169.254/32", "fd00:ec2::254/128"}},
		{token: "api.github.com", host: "api.github.com"},
		{token: "tcp:api.github.com:443", proto: "tcp", host: "api.github.com", ports: []portRange{{443, 443}}},

		{token: "", wantError: true},
		{token: "10.0.0.0/64", wantError: true},
		{token: "tcp:1.2.3.4:notaport", wantError: true},
		{token: "tcp:1.2.3.4:99999", wantError: true},
		{token: "tcp:[2001:db8::/32", wantError: true},
		{token: "!!!", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.token, func(t *testing.T) {
			r, err := parseRule(actionAllow, tc.token, ctx)
			if tc.wantError {
				if err == nil {
					t.Fatalf("parseRule(%q) = %v, want error", tc.token, r)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRule(%q): %v", tc.token, err)
			}
			if r.proto != tc.proto {
				t.Errorf("proto = %q, want %q", r.proto, tc.proto)
			}
			if r.host != tc.host {
				t.Errorf("host = %q, want %q", r.host, tc.host)
			}
			var got []string
			for _, n := range r.prefixes() {
				got = append(got, n.String())
			}
			if strings.Join(got, ",") != strings.Join(tc.nets, ",") {
				t.Errorf("nets = %v, want %v", got, tc.nets)
			}
			if len(r.ports) != len(tc.ports) {
				t.Fatalf("ports = %v, want %v", r.ports, tc.ports)
			}
			for i := range r.ports {
				if r.ports[i] != tc.ports[i] {
					t.Errorf("ports[%d] = %v, want %v", i, r.ports[i], tc.ports[i])
				}
			}
		})
	}
}

func TestRuleMatching(t *testing.T) {
	ctx := aliasContext{}
	mk := func(tok string) *rule {
		r, err := parseRule(actionDeny, tok, ctx)
		if err != nil {
			t.Fatalf("parseRule(%q): %v", tok, err)
		}
		return r
	}

	addr := netip.MustParseAddr("10.1.2.3")

	if !mk("10.0.0.0/8").matches(addr, "tcp", 80, true) {
		t.Error("CIDR rule should match any protocol and port")
	}
	if mk("tcp:10.0.0.0/8").matches(addr, "udp", 80, true) {
		t.Error("tcp rule matched a udp packet")
	}
	if !mk("tcp:10.0.0.0/8:80,443").matches(addr, "tcp", 443, true) {
		t.Error("port list should match 443")
	}
	if mk("tcp:10.0.0.0/8:80,443").matches(addr, "tcp", 8443, true) {
		t.Error("port list should not match 8443")
	}
	// A port-constrained rule cannot decide a fragment with no transport header.
	if mk("tcp:10.0.0.0/8:80").matches(addr, "tcp", 0, false) {
		t.Error("port rule matched a packet without ports")
	}
	// An address-only rule still covers fragments.
	if !mk("10.0.0.0/8").matches(addr, "tcp", 0, false) {
		t.Error("address rule should match a packet without ports")
	}
	if mk("192.168.0.0/16").matches(addr, "tcp", 80, true) {
		t.Error("unrelated subnet matched")
	}
}

func TestBuildRulesPolicySemantics(t *testing.T) {
	cfg := testConfig(t)

	t.Run("default is allow-all", func(t *testing.T) {
		out, _, err := buildRules(cfg, envMap(nil))
		if err != nil {
			t.Fatal(err)
		}
		if out.fallback != actionAllow || len(out.rules) != 0 {
			t.Fatalf("empty config produced %d rules, default %s", len(out.rules), out.fallback)
		}
	})

	t.Run("NET_ALLOW implies deny-by-default", func(t *testing.T) {
		out, _, err := buildRules(cfg, envMap(map[string]string{"NET_ALLOW": "1.2.3.4"}))
		if err != nil {
			t.Fatal(err)
		}
		if out.fallback != actionDeny || !out.implicit {
			t.Fatalf("fallback = %s implicit=%v, want deny/true", out.fallback, out.implicit)
		}
	})

	t.Run("explicit NET_POLICY wins", func(t *testing.T) {
		out, _, err := buildRules(cfg, envMap(map[string]string{
			"NET_ALLOW": "1.2.3.4", "NET_POLICY": "allow",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if out.fallback != actionAllow {
			t.Fatalf("fallback = %s, want allow", out.fallback)
		}
	})

	t.Run("deny is evaluated before allow", func(t *testing.T) {
		out, _, err := buildRules(cfg, envMap(map[string]string{
			"NET_DENY":  "10.0.0.5",
			"NET_ALLOW": "10.0.0.0/8",
		}))
		if err != nil {
			t.Fatal(err)
		}
		act, _ := out.decide(netip.MustParseAddr("10.0.0.5"), "tcp", 80, true)
		if act != actionDeny {
			t.Errorf("10.0.0.5 = %s, want deny", act)
		}
		act, _ = out.decide(netip.MustParseAddr("10.0.0.6"), "tcp", 80, true)
		if act != actionAllow {
			t.Errorf("10.0.0.6 = %s, want allow", act)
		}
	})

	t.Run("NET_RULES keeps its written order", func(t *testing.T) {
		out, _, err := buildRules(cfg, envMap(map[string]string{
			"NET_RULES": "allow:tcp:10.0.0.5:22 deny:10.0.0.0/8 allow:any",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if act, _ := out.decide(netip.MustParseAddr("10.0.0.5"), "tcp", 22, true); act != actionAllow {
			t.Errorf("10.0.0.5:22 = %s, want allow", act)
		}
		if act, _ := out.decide(netip.MustParseAddr("10.0.0.5"), "tcp", 80, true); act != actionDeny {
			t.Errorf("10.0.0.5:80 = %s, want deny", act)
		}
		if act, _ := out.decide(netip.MustParseAddr("8.8.8.8"), "tcp", 80, true); act != actionAllow {
			t.Errorf("8.8.8.8 = %s, want allow", act)
		}
	})

	t.Run("invalid rules are reported", func(t *testing.T) {
		if _, _, err := buildRules(cfg, envMap(map[string]string{"NET_ALLOW": "300.1.1.1/8"})); err == nil {
			t.Fatal("expected an error for a malformed CIDR")
		}
		if _, _, err := buildRules(cfg, envMap(map[string]string{"NET_POLICY": "maybe"})); err == nil {
			t.Fatal("expected an error for an unknown policy")
		}
		if _, _, err := buildRules(cfg, envMap(map[string]string{"NET_PRESET": "nonsense"})); err == nil {
			t.Fatal("expected an error for an unknown preset")
		}
	})
}

func TestPresets(t *testing.T) {
	cfg := testConfig(t)

	cases := []struct {
		preset string
		addr   string
		want   action
	}{
		{"internet", "10.1.2.3", actionDeny},
		{"internet", "192.168.1.10", actionDeny},
		{"internet", "169.254.169.254", actionDeny},
		{"internet", "8.8.8.8", actionAllow},
		{"lan", "192.168.1.10", actionAllow},
		{"lan", "8.8.8.8", actionDeny},
		{"isolated", "8.8.8.8", actionDeny},
		{"isolated", "10.1.2.3", actionDeny},
		{"open", "8.8.8.8", actionAllow},
		{"open", "10.1.2.3", actionAllow},
	}

	for _, tc := range cases {
		t.Run(tc.preset+"/"+tc.addr, func(t *testing.T) {
			out, _, err := buildRules(cfg, envMap(map[string]string{"NET_PRESET": tc.preset}))
			if err != nil {
				t.Fatal(err)
			}
			if act, _ := out.decide(netip.MustParseAddr(tc.addr), "tcp", 443, true); act != tc.want {
				t.Errorf("preset %s, %s = %s, want %s", tc.preset, tc.addr, act, tc.want)
			}
		})
	}
}

func TestBlockPrivateShortcut(t *testing.T) {
	cfg := testConfig(t)
	out, _, err := buildRules(cfg, envMap(map[string]string{"NET_BLOCK_PRIVATE": "Y"}))
	if err != nil {
		t.Fatal(err)
	}
	if act, _ := out.decide(netip.MustParseAddr("172.20.0.5"), "tcp", 80, true); act != actionDeny {
		t.Errorf("172.20.0.5 = %s, want deny", act)
	}
	if act, _ := out.decide(netip.MustParseAddr("1.1.1.1"), "tcp", 80, true); act != actionAllow {
		t.Errorf("1.1.1.1 = %s, want allow", act)
	}
}

func TestIngressRules(t *testing.T) {
	cfg := testConfig(t)
	_, in, err := buildRules(cfg, envMap(map[string]string{"NET_ALLOW_IN": "192.168.5.0/24"}))
	if err != nil {
		t.Fatal(err)
	}
	if in.fallback != actionDeny {
		t.Fatalf("ingress fallback = %s, want deny", in.fallback)
	}
	if act, _ := in.decide(netip.MustParseAddr("192.168.5.9"), "tcp", 22, true); act != actionAllow {
		t.Error("allowed ingress source was denied")
	}
	if act, _ := in.decide(netip.MustParseAddr("192.168.6.9"), "tcp", 22, true); act != actionDeny {
		t.Error("unlisted ingress source was allowed")
	}
}

func TestRulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	content := `# guest may only reach the package mirrors and its own gateway
allow tcp:archive.ubuntu.com:80,443
allow tcp:1.1.1.1:443

deny  private        # never the host LAN
allow any            # everything else is fine
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	tokens, err := readRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"allow:tcp:archive.ubuntu.com:80,443",
		"allow:tcp:1.1.1.1:443",
		"deny:private",
		"allow:any",
	}
	if len(tokens) != len(want) {
		t.Fatalf("tokens = %v, want %v", tokens, want)
	}
	for i := range want {
		if tokens[i] != want[i] {
			t.Errorf("tokens[%d] = %q, want %q", i, tokens[i], want[i])
		}
	}

	cfg := testConfig(t)
	cfg.RulesFile = path
	out, _, err := buildRules(cfg, envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if act, _ := out.decide(netip.MustParseAddr("192.168.1.1"), "tcp", 80, true); act != actionDeny {
		t.Error("file rule 'deny private' was not applied")
	}
	if act, _ := out.decide(netip.MustParseAddr("9.9.9.9"), "tcp", 80, true); act != actionAllow {
		t.Error("file rule 'allow any' was not applied")
	}
}

func TestMissingRulesFileIsNotAnError(t *testing.T) {
	tokens, err := readRulesFile(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil || tokens != nil {
		t.Fatalf("readRulesFile(absent) = %v, %v; want nil, nil", tokens, err)
	}
}

func TestHostResolverKeepsLastAnswerOnFailure(t *testing.T) {
	r, err := parseRule(actionAllow, "example.test", aliasContext{})
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	res := &hostResolver{targets: []*rule{r}, lookup: func(string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		}
		return nil, os.ErrDeadlineExceeded
	}}

	res.refresh()
	if got := r.prefixes(); len(got) != 1 || got[0].String() != "203.0.113.7/32" {
		t.Fatalf("after first refresh: %v", got)
	}

	res.refresh() // resolver now fails
	if got := r.prefixes(); len(got) != 1 || got[0].String() != "203.0.113.7/32" {
		t.Fatalf("a failed lookup changed the ACL: %v", got)
	}
}

func TestSplitListSeparators(t *testing.T) {
	got := splitList(" a.b, c.d;e.f\n g.h\t")
	want := []string{"a.b", "c.d", "e.f", "g.h"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
}
