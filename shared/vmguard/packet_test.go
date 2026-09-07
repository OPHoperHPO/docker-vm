package main

import (
	"encoding/binary"
	"testing"
)

func TestDecodeIPv4TCP(t *testing.T) {
	frame := tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)
	p := decode(frame)

	if !p.ip || p.v6 {
		t.Fatalf("ip=%v v6=%v, want an IPv4 packet", p.ip, p.v6)
	}
	if p.src.String() != "20.20.20.21" || p.dst.String() != "8.8.8.8" {
		t.Errorf("addresses = %s -> %s", p.src, p.dst)
	}
	if p.proto != protoTCP || !p.hasPorts || p.dstPort != 443 || p.srcPort != 45000 {
		t.Errorf("transport = proto %d %d -> %d (hasPorts=%v)", p.proto, p.srcPort, p.dstPort, p.hasPorts)
	}
	if p.tcpFlags != tcpFlagSYN || p.tcpSeq != 1000 {
		t.Errorf("tcp flags=%#x seq=%d", p.tcpFlags, p.tcpSeq)
	}
	if p.protoName() != "tcp" {
		t.Errorf("protoName = %q", p.protoName())
	}
}

func TestDecodeIPv4UDPWithVLAN(t *testing.T) {
	frame := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "1.1.1.1", proto: protoUDP,
		srcPort: 5000, dstPort: 53, vlan: true, payload: []byte("q"),
	})
	p := decode(frame)

	if !p.ip || p.proto != protoUDP {
		t.Fatalf("VLAN-tagged frame did not decode: ip=%v proto=%d", p.ip, p.proto)
	}
	if p.dstPort != 53 {
		t.Errorf("dstPort = %d, want 53", p.dstPort)
	}
}

func TestDecodeIPv4Fragment(t *testing.T) {
	frame := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "8.8.8.8", proto: protoTCP,
		srcPort: 45000, dstPort: 443, fragOffset: 185,
	})
	p := decode(frame)

	if !p.fragment {
		t.Fatal("non-first fragment was not flagged")
	}
	if p.hasPorts {
		t.Error("ports must not be trusted on a non-first fragment")
	}
	if p.dst.String() != "8.8.8.8" {
		t.Errorf("dst = %s, addresses are still readable on a fragment", p.dst)
	}
}

func TestDecodeIPv6WithExtensionHeaders(t *testing.T) {
	// Hop-by-hop (next=destination options), destination options (next=TCP).
	ext := []byte{
		60, 0, 0, 0, 0, 0, 0, 0, // hop-by-hop, next = 60, len 0 => 8 bytes
		protoTCP, 0, 0, 0, 0, 0, 0, 0, // dest opts, next = TCP, len 0 => 8 bytes
	}
	frame := buildFrame(t, frameOpts{
		src: "fd00::21", dst: "2001:db8::1", proto: protoTCP,
		srcPort: 45000, dstPort: 443, tcpFlags: tcpFlagSYN,
		v6ExtHeaders: ext, v6ExtNext: 0,
	})

	p := decode(frame)
	if !p.ip || !p.v6 {
		t.Fatalf("ip=%v v6=%v", p.ip, p.v6)
	}
	if p.proto != protoTCP || !p.hasPorts || p.dstPort != 443 {
		t.Fatalf("transport not reached through extension headers: proto=%d port=%d hasPorts=%v",
			p.proto, p.dstPort, p.hasPorts)
	}
	if p.dst.String() != "2001:db8::1" {
		t.Errorf("dst = %s", p.dst)
	}
}

func TestDecodeARPIsNotIP(t *testing.T) {
	frame := make([]byte, 0, 42)
	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	frame = append(frame, guestMAC...)
	frame = binary.BigEndian.AppendUint16(frame, ethTypeARP)
	frame = append(frame, make([]byte, 28)...)

	p := decode(frame)
	if p.ip {
		t.Fatal("ARP frame decoded as IP")
	}
	if p.etherType != ethTypeARP {
		t.Errorf("etherType = %#x", p.etherType)
	}
}

func TestDecodeTruncatedFrames(t *testing.T) {
	full := tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)

	for n := 0; n < len(full); n++ {
		p := decode(full[:n])
		// The only requirement is that decoding never panics and never claims
		// transport information it could not read.
		if p.hasPorts && n < 14+20+20 {
			t.Fatalf("truncated to %d bytes but ports were reported", n)
		}
	}
}

func TestDecodeRejectsBadIPVersion(t *testing.T) {
	frame := tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)
	frame[14] = 0x35 // version 3, IHL 5
	if p := decode(frame); p.ip {
		t.Fatal("frame with IP version 3 was accepted as IPv4")
	}
}

func TestDecodeRejectsShortIHL(t *testing.T) {
	frame := tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)
	frame[14] = 0x43 // version 4, IHL 3 (below the 5-word minimum)
	if p := decode(frame); p.ip {
		t.Fatal("frame with an undersized IHL was accepted")
	}
}

func TestTruncatedFirstFragmentIsFlagged(t *testing.T) {
	// A first fragment carrying only 8 of the 20 TCP header bytes: enough to
	// reassemble at the far end, not enough for a port rule to see the port.
	frame := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "8.8.8.8", proto: protoTCP,
		srcPort: 45000, dstPort: 443, tcpFlags: tcpFlagSYN,
		moreFragments: true, truncateL4: 8,
	})

	p := decode(frame)
	if p.hasPorts {
		t.Fatal("ports were read from an incomplete TCP header")
	}
	if !p.moreFrags || p.fragment {
		t.Fatalf("moreFrags=%v fragment=%v, want a first fragment", p.moreFrags, p.fragment)
	}
	if !p.truncatedFirstFragment() {
		t.Fatal("the truncated first fragment was not recognised")
	}

	// A complete first fragment of a genuinely fragmented datagram is normal.
	whole := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "8.8.8.8", proto: protoTCP,
		srcPort: 45000, dstPort: 443, tcpFlags: tcpFlagSYN,
		moreFragments: true,
	})
	if decode(whole).truncatedFirstFragment() {
		t.Error("a complete first fragment was treated as truncated")
	}

	// An unfragmented packet must never be flagged.
	if decode(tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)).truncatedFirstFragment() {
		t.Error("an unfragmented packet was treated as a truncated fragment")
	}
}
