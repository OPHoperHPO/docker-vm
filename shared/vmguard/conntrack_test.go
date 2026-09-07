package main

import (
	"testing"
	"time"
)

// inboundSSH is a connection forwarded into the guest from the container
// gateway — a private address that "deny private" would otherwise refuse.
func inboundSSH(t *testing.T, flags uint8, seq uint32) []byte {
	t.Helper()
	return buildFrame(t, frameOpts{
		src: "172.17.0.1", dst: "20.20.20.21", proto: protoTCP,
		srcPort: 51000, dstPort: 22, tcpFlags: flags, tcpSeq: seq,
	})
}

func outboundSSHReply(t *testing.T, flags uint8) []byte {
	t.Helper()
	return buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "172.17.0.1", proto: protoTCP,
		srcPort: 22, dstPort: 51000, tcpFlags: flags, tcpSeq: 7000, tcpAck: 1,
	})
}

func TestRepliesToForwardedConnectionsAreAllowed(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "internet"})

	// Without the inbound packet first, the reply looks like the guest
	// initiating a connection into the private network, and is refused.
	if v := f.inspect(decode(outboundSSHReply(t, tcpFlagSYN|tcpFlagACK)), egress); v.act != actionDeny {
		t.Fatalf("unsolicited traffic to a private address was allowed (%s)", v.reason)
	}

	f2 := buildFilter(t, cfg, map[string]string{"NET_PRESET": "internet"})

	if v := f2.inspect(decode(inboundSSH(t, tcpFlagSYN, 100)), ingress); v.act != actionAllow {
		t.Fatalf("forwarded SSH connection was denied on the way in (%s)", v.reason)
	}
	v := f2.inspect(decode(outboundSSHReply(t, tcpFlagSYN|tcpFlagACK)), egress)
	if v.act != actionAllow {
		t.Fatalf("the reply to a forwarded connection was denied (%s)", v.reason)
	}
	if v.reason != "established" {
		t.Errorf("reply allowed for the wrong reason: %q", v.reason)
	}
}

func TestRepliesToGuestInitiatedFlowsAreAllowed(t *testing.T) {
	cfg := testConfig(t)
	// Ingress is locked down: only the flows the guest itself started may come
	// back in.
	f := buildFilter(t, cfg, map[string]string{"NET_POLICY_IN": "deny"})

	answer := buildFrame(t, frameOpts{
		src: "93.184.216.34", dst: "20.20.20.21", proto: protoTCP,
		srcPort: 443, dstPort: 45000, tcpFlags: tcpFlagSYN | tcpFlagACK,
	})

	if v := f.inspect(decode(answer), ingress); v.act != actionDeny {
		t.Fatal("unsolicited inbound traffic was allowed under NET_POLICY_IN=deny")
	}

	f2 := buildFilter(t, cfg, map[string]string{"NET_POLICY_IN": "deny"})
	if v := f2.inspect(decode(tcpSyn(t, "20.20.20.21", "93.184.216.34", 443)), egress); v.act != actionAllow {
		t.Fatal("the guest could not open the connection")
	}
	if v := f2.inspect(decode(answer), ingress); v.act != actionAllow {
		t.Fatalf("the answer to the guest's own connection was denied (%s)", v.reason)
	}
}

func TestBlockedPacketsDoNotCreateFlows(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_DENY": "10.0.0.0/8"})

	frame := tcpSyn(t, "20.20.20.21", "10.1.2.3", 22)
	for i := 0; i < 3; i++ {
		if v := f.inspect(decode(frame), egress); v.act != actionDeny {
			t.Fatalf("attempt %d was allowed (%s) — a blocked packet opened a flow", i+1, v.reason)
		}
	}
	if n := f.flows.size(); n != 0 {
		t.Errorf("conntrack holds %d entries after only blocked traffic", n)
	}
}

func TestResetClosesTheFlow(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "internet"})

	if v := f.inspect(decode(inboundSSH(t, tcpFlagSYN, 100)), ingress); v.act != actionAllow {
		t.Fatal("inbound connection was denied")
	}
	if v := f.inspect(decode(outboundSSHReply(t, tcpFlagACK)), egress); v.act != actionAllow {
		t.Fatal("reply on the established flow was denied")
	}

	// The peer resets the connection; the entry must go with it.
	if v := f.inspect(decode(inboundSSH(t, tcpFlagRST, 101)), ingress); v.act != actionAllow {
		t.Fatal("the reset itself was denied")
	}
	if n := f.flows.size(); n != 0 {
		t.Fatalf("conntrack still holds %d entries after a reset", n)
	}
	if v := f.inspect(decode(outboundSSHReply(t, tcpFlagACK)), egress); v.act != actionDeny {
		t.Fatal("traffic on a closed flow was still allowed")
	}
}

func TestStatelessModeMatchesEveryPacket(t *testing.T) {
	cfg := testConfig(t)
	cfg.Stateful = false
	f := buildFilter(t, cfg, map[string]string{"NET_PRESET": "internet"})

	if f.flows != nil {
		t.Fatal("conntrack was created although NET_GUARD_STATEFUL is off")
	}
	if v := f.inspect(decode(inboundSSH(t, tcpFlagSYN, 100)), ingress); v.act != actionAllow {
		t.Fatal("inbound connection was denied")
	}
	if v := f.inspect(decode(outboundSSHReply(t, tcpFlagSYN|tcpFlagACK)), egress); v.act != actionDeny {
		t.Fatal("stateless mode should judge the reply on its own address")
	}
}

func TestConntrackExpiresIdleFlows(t *testing.T) {
	c := newConntrack(16)
	now := time.Now()

	udp := flowKey{proto: protoUDP, peer: mustAddr(t, "1.2.3.4"), peerPort: 53,
		local: mustAddr(t, "20.20.20.21"), localPort: 45000}
	tcp := flowKey{proto: protoTCP, peer: mustAddr(t, "1.2.3.4"), peerPort: 443,
		local: mustAddr(t, "20.20.20.21"), localPort: 45001}

	c.record(udp, now.Add(-otherIdleTimeout-time.Minute))
	c.record(tcp, now.Add(-otherIdleTimeout-time.Minute))

	c.mu.Lock()
	c.sweepLocked(now)
	c.mu.Unlock()

	if c.seen(udp, now) {
		t.Error("an idle UDP flow survived the sweep")
	}
	if !c.seen(tcp, now) {
		t.Error("a TCP flow was expired at the UDP timeout")
	}
}

func TestConntrackEvictsOldestWhenFull(t *testing.T) {
	const capacity = 8
	c := newConntrack(capacity)
	now := time.Now()

	var newest flowKey
	for i := 0; i < capacity*3; i++ {
		k := flowKey{
			proto: protoTCP, peer: mustAddr(t, "1.2.3.4"), peerPort: uint16(1000 + i),
			local: mustAddr(t, "20.20.20.21"), localPort: 45000,
		}
		c.record(k, now.Add(time.Duration(i)*time.Second))
		newest = k
	}

	if n := c.size(); n > capacity {
		t.Errorf("conntrack grew to %d entries, cap is %d", n, capacity)
	}
	if !c.seen(newest, now) {
		t.Error("the most recently used flow was evicted")
	}
}

func TestReloadDropsTrackedFlows(t *testing.T) {
	cfg := testConfig(t)
	f := buildFilter(t, cfg, nil)

	frame := decode(tcpSyn(t, "20.20.20.21", "10.1.2.3", 22))
	if v := f.inspect(frame, egress); v.act != actionAllow {
		t.Fatal("the open policy should have allowed this")
	}
	if f.flows.size() == 0 {
		t.Fatal("the allowed flow was not tracked")
	}

	// Tightening the rules must take effect on connections that are already
	// open, not only on new ones.
	tighter, in, err := buildRules(cfg, envMap(map[string]string{"NET_DENY": "10.0.0.0/8"}))
	if err != nil {
		t.Fatal(err)
	}
	f.setRules(tighter, in)

	if n := f.flows.size(); n != 0 {
		t.Fatalf("conntrack kept %d entries across a rule change", n)
	}
	if v := f.inspect(frame, egress); v.act != actionDeny {
		t.Fatalf("an open flow survived a policy that now denies it (%s)", v.reason)
	}
}
