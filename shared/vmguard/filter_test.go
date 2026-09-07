package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func TestEssentialFlowsSurviveADenyAllPolicy(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	cases := []struct {
		name  string
		frame []byte
		want  action
	}{
		{"dhcp discover", buildFrame(t, frameOpts{
			src: "0.0.0.0", dst: "255.255.255.255", proto: protoUDP,
			srcPort: 68, dstPort: 67, payload: []byte("x"),
		}), actionAllow},
		{"dns to gateway", udpTo(t, "20.20.20.21", "20.20.20.1", 53), actionAllow},
		{"dns over tcp to gateway", func() []byte {
			return buildFrame(t, frameOpts{
				src: "20.20.20.21", dst: "20.20.20.1", proto: protoTCP,
				srcPort: 45000, dstPort: 53, tcpFlags: tcpFlagSYN,
			})
		}(), actionAllow},
		{"dns to a third party", udpTo(t, "20.20.20.21", "8.8.8.8", 53), actionDeny},
		{"http to the internet", tcpSyn(t, "20.20.20.21", "93.184.216.34", 80), actionDeny},
		{"ssh to the gateway", tcpSyn(t, "20.20.20.21", "20.20.20.1", 22), actionDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := f.inspect(decode(tc.frame), egress)
			if v.act != tc.want {
				t.Errorf("verdict = %s (%s), want %s", v.act, v.reason, tc.want)
			}
		})
	}
}

func TestStrictModeDropsEvenDHCP(t *testing.T) {
	cfg := testConfig(t)
	cfg.Strict = true
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	frame := buildFrame(t, frameOpts{
		src: "0.0.0.0", dst: "255.255.255.255", proto: protoUDP,
		srcPort: 68, dstPort: 67, payload: []byte("x"),
	})
	if v := f.inspect(decode(frame), egress); v.act != actionDeny {
		t.Errorf("DHCP verdict = %s, want deny under NET_GUARD_STRICT", v.act)
	}
}

func TestARPIsAlwaysAllowed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Strict = true
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	arp := make([]byte, 60)
	copy(arp[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(arp[6:12], guestMAC)
	arp[12], arp[13] = 0x08, 0x06

	if v := f.inspect(decode(arp), egress); v.act != actionAllow {
		t.Fatalf("ARP verdict = %s; the link cannot come up without it", v.act)
	}
}

func TestNDPIsAllowed(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	// Neighbour solicitation (ICMPv6 type 135).
	frame := buildFrame(t, frameOpts{
		src: "fd00::21", dst: "ff02::1:ff00:1", proto: protoICMPv6, payload: []byte{135},
	})
	if v := f.inspect(decode(frame), egress); v.act != actionAllow {
		t.Errorf("neighbour solicitation verdict = %s, want allow", v.act)
	}
}

func TestIngressUsesSourceAddress(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_ALLOW_IN": "203.0.113.0/24"})

	ok := buildFrame(t, frameOpts{
		src: "203.0.113.5", dst: "20.20.20.21", proto: protoTCP,
		srcPort: 5000, dstPort: 22, tcpFlags: tcpFlagSYN,
	})
	if v := f.inspect(decode(ok), ingress); v.act != actionAllow {
		t.Errorf("allowed source was denied: %s", v.reason)
	}

	bad := buildFrame(t, frameOpts{
		src: "198.51.100.5", dst: "20.20.20.21", proto: protoTCP,
		srcPort: 5000, dstPort: 22, tcpFlags: tcpFlagSYN,
	})
	if v := f.inspect(decode(bad), ingress); v.act != actionDeny {
		t.Errorf("unlisted source was allowed: %s", v.reason)
	}

	// Egress is unaffected by the ingress ACL.
	if v := f.inspect(decode(tcpSyn(t, "20.20.20.21", "198.51.100.5", 443)), egress); v.act != actionAllow {
		t.Errorf("egress verdict = %s, want allow", v.act)
	}
}

func TestFragmentsAreJudgedByAddress(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_DENY": "10.0.0.0/8"})

	frag := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "10.9.9.9", proto: protoTCP,
		srcPort: 45000, dstPort: 443, fragOffset: 185,
	})
	if v := f.inspect(decode(frag), egress); v.act != actionDeny {
		t.Error("a fragment towards a denied subnet slipped through")
	}
}

func TestBlockLogDeduplicates(t *testing.T) {
	cfg := testConfig(t)
	cfg.LogMode = logBlocked
	f := buildFilter(t, cfg, map[string]string{"NET_DENY": "10.0.0.0/8"})

	p := decode(tcpSyn(t, "20.20.20.21", "10.1.2.3", 22))
	v := f.inspect(p, egress)
	now := time.Now()

	if line := f.note(p, egress, v, now); line == "" {
		t.Fatal("the first blocked flow produced no log line")
	}
	if line := f.note(p, egress, v, now); line != "" {
		t.Fatalf("a repeated flow logged again: %q", line)
	}

	entries := f.blocks.snapshot()
	if len(entries) != 1 || entries[0].Count != 2 {
		t.Fatalf("block log = %+v, want one entry seen twice", entries)
	}
	if f.stats.deniedOut.Load() != 2 {
		t.Errorf("deniedOut = %d, want 2", f.stats.deniedOut.Load())
	}
}

func TestReloadPicksUpFileChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(path, []byte("allow any\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t)
	cfg.RulesFile = path

	out, in, err := buildRules(cfg, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	f := newFilter(cfg, out, in)

	blocked := decode(tcpSyn(t, "20.20.20.21", "10.1.2.3", 22))
	if v := f.inspect(blocked, egress); v.act != actionAllow {
		t.Fatal("initial policy should allow everything")
	}

	go watchRules(cfg, f, nil, 10*time.Millisecond)

	// Ensure the modification time really moves for coarse filesystem clocks.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("deny private\nallow any\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f.inspect(blocked, egress).act == actionDeny {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the rules file change was never picked up")
}

func TestReloadKeepsPolicyWhenFileVanishes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(path, []byte("deny private\nallow any\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t)
	cfg.RulesFile = path
	out, in, err := buildRules(cfg, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	f := newFilter(cfg, out, in)

	go watchRules(cfg, f, nil, 10*time.Millisecond)

	time.Sleep(20 * time.Millisecond)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	blocked := decode(tcpSyn(t, "20.20.20.21", "10.1.2.3", 22))
	if v := f.inspect(blocked, egress); v.act != actionDeny {
		t.Fatal("a deleted rules file dropped the running policy")
	}
}

func TestReloadKeepsPolicyWhenFileIsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(path, []byte("deny private\nallow any\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t)
	cfg.RulesFile = path
	out, in, err := buildRules(cfg, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	f := newFilter(cfg, out, in)

	go watchRules(cfg, f, nil, 10*time.Millisecond)

	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("deny 999.999.999.999/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	blocked := decode(tcpSyn(t, "20.20.20.21", "10.1.2.3", 22))
	if v := f.inspect(blocked, egress); v.act != actionDeny {
		t.Fatal("an unparsable rules file relaxed the running policy")
	}
}

// The DHCP allowance must not become a way around the ACL. Every field below
// is chosen by the guest, so anything the exemption does not pin down is a
// destination the guest can reach regardless of the policy.
func TestDHCPAllowanceCannotBeUsedToReachDeniedHosts(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	cases := []struct {
		name             string
		dst              string
		srcPort, dstPort uint16
		want             action
	}{
		{"real discover to the broadcast address", "255.255.255.255", 68, 67, actionAllow},
		{"real request to the gateway", "20.20.20.1", 68, 67, actionAllow},

		{"client port, arbitrary host and port", "10.1.2.3", 68, 5432, actionDeny},
		{"server port as source, arbitrary host", "10.1.2.3", 67, 5432, actionDeny},
		{"dhcp port pair to an unrelated host", "93.184.216.34", 68, 67, actionDeny},
		{"server port as destination on a third party", "10.1.2.3", 45000, 67, actionDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := buildFrame(t, frameOpts{
				src: "20.20.20.21", dst: tc.dst, proto: protoUDP,
				srcPort: tc.srcPort, dstPort: tc.dstPort, payload: []byte("x"),
			})
			if v := f.inspect(decode(frame), egress); v.act != tc.want {
				t.Errorf("udp %s:%d -> %s:%d = %s (%s), want %s",
					"20.20.20.21", tc.srcPort, tc.dst, tc.dstPort, v.act, v.reason, tc.want)
			}
		})
	}
}

func TestDHCPv6AllowanceIsScoped(t *testing.T) {
	cfg := testConfig(t)
	cfg.Gateway = mustAddr(t, "fd00::1")
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	mk := func(dst string, sp, dp uint16) *packet {
		return decode(buildFrame(t, frameOpts{
			src: "fd00::21", dst: dst, proto: protoUDP,
			srcPort: sp, dstPort: dp, payload: []byte("x"),
		}))
	}

	if v := f.inspect(mk("ff02::1:2", 546, 547), egress); v.act != actionAllow {
		t.Errorf("real DHCPv6 solicit was denied (%s)", v.reason)
	}
	if v := f.inspect(mk("2001:db8::1", 546, 5432), egress); v.act != actionDeny {
		t.Errorf("DHCPv6 client port reached an arbitrary host and port (%s)", v.reason)
	}
	if v := f.inspect(mk("2001:db8::1", 546, 547), egress); v.act != actionDeny {
		t.Errorf("DHCPv6 port pair reached an off-link host (%s)", v.reason)
	}
}

// Neighbour discovery is link-local by definition; the exemption must not carry
// ICMPv6 to arbitrary routable addresses.
func TestNDPAllowanceIsLinkLocal(t *testing.T) {
	cfg := testConfig(t)
	cfg.Gateway = mustAddr(t, "fd00::1")
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "isolated"})

	onLink := buildFrame(t, frameOpts{
		src: "fd00::21", dst: "ff02::1:ff00:1", proto: protoICMPv6, payload: []byte{135},
	})
	if v := f.inspect(decode(onLink), egress); v.act != actionAllow {
		t.Errorf("neighbour solicitation to a solicited-node multicast address was denied (%s)", v.reason)
	}

	offLink := buildFrame(t, frameOpts{
		src: "fd00::21", dst: "2001:db8::1", proto: protoICMPv6, payload: []byte{135},
	})
	if v := f.inspect(decode(offLink), egress); v.act != actionDeny {
		t.Errorf("an NDP-typed packet reached a routable address (%s)", v.reason)
	}
}

// A port-constrained rule cannot judge a packet whose ports were left out of
// the first fragment, so the packet must not slip through on the default.
func TestTruncatedFirstFragmentIsDenied(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_DENY": "tcp:*:22"})

	// The same destination and port, hidden behind a first fragment that stops
	// before the port field.
	hidden := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "203.0.113.9", proto: protoTCP,
		srcPort: 45000, dstPort: 22, tcpFlags: tcpFlagSYN,
		moreFragments: true, truncateL4: 8,
	})
	v := f.inspect(decode(hidden), egress)
	if v.act != actionDeny {
		t.Fatalf("a truncated first fragment was allowed (%s) past a port rule", v.reason)
	}
	if v.reason != "truncated-fragment" {
		t.Errorf("reason = %q, want truncated-fragment", v.reason)
	}

	// Ordinary fragmented traffic still flows.
	ok := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "203.0.113.9", proto: protoUDP,
		srcPort: 45000, dstPort: 4433, payload: make([]byte, 64),
		moreFragments: true,
	})
	if v := f.inspect(decode(ok), egress); v.act != actionAllow {
		t.Errorf("a normal fragmented datagram was denied (%s)", v.reason)
	}
}
