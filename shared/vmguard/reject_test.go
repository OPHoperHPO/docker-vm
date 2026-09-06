package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// checksumOver recomputes the internet checksum across a buffer that already
// contains its own checksum; a correct one always sums to zero.
func checksumOver(b []byte) uint16 { return checksum(b) }

func TestChecksumKnownVector(t *testing.T) {
	// RFC 1071 worked example.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := checksum(data); got != 0x220d {
		t.Fatalf("checksum = %#x, want 0x220d", got)
	}
}

func TestChecksumOddLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	// Padding with a zero byte must not change the result.
	if checksum(data) != checksum([]byte{0x01, 0x02, 0x03, 0x00}) {
		t.Fatal("odd-length checksum does not match its zero-padded form")
	}
}

func TestTCPResetForSYN(t *testing.T) {
	frame := tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)
	p := decode(frame)

	rst := tcpReset(p)
	if rst == nil {
		t.Fatal("no reset generated for a SYN")
	}

	// Addressed back to the guest, from the address it tried to reach.
	if !bytes.Equal(rst[0:6], guestMAC) {
		t.Errorf("destination MAC = %x, want the guest", rst[0:6])
	}
	if !bytes.Equal(rst[6:12], gwMAC) {
		t.Errorf("source MAC = %x, want the gateway", rst[6:12])
	}
	if et := binary.BigEndian.Uint16(rst[12:14]); et != ethTypeIPv4 {
		t.Fatalf("ethertype = %#x", et)
	}

	ip := rst[14:34]
	if checksumOver(ip) != 0 {
		t.Error("IPv4 header checksum is wrong")
	}
	if got := netip.AddrFrom4([4]byte(ip[12:16])).String(); got != "8.8.8.8" {
		t.Errorf("reset source = %s, want 8.8.8.8", got)
	}
	if got := netip.AddrFrom4([4]byte(ip[16:20])).String(); got != "20.20.20.21" {
		t.Errorf("reset destination = %s, want the guest", got)
	}

	tcp := rst[34 : 34+20]
	if binary.BigEndian.Uint16(tcp[0:2]) != 443 || binary.BigEndian.Uint16(tcp[2:4]) != 45000 {
		t.Errorf("ports = %d -> %d, want 443 -> 45000",
			binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]))
	}
	if tcp[13] != tcpFlagRST|tcpFlagACK {
		t.Errorf("flags = %#x, want RST|ACK", tcp[13])
	}
	// A SYN consumes one sequence number, so the reset acknowledges seq+1.
	if got := binary.BigEndian.Uint32(tcp[8:12]); got != 1001 {
		t.Errorf("ack = %d, want 1001", got)
	}

	sum := pseudoHeaderSum(
		netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("20.20.20.21"), protoTCP, 20)
	if finishChecksum(partialChecksum(tcp, sum)) != 0 {
		t.Error("TCP checksum is wrong")
	}

	if len(rst) < 60 {
		t.Errorf("frame is %d bytes, below the 60-byte Ethernet minimum", len(rst))
	}
}

func TestTCPResetForEstablishedSegment(t *testing.T) {
	frame := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "8.8.8.8", proto: protoTCP,
		srcPort: 45000, dstPort: 443,
		tcpFlags: tcpFlagACK, tcpSeq: 5000, tcpAck: 9000,
		payload: []byte("hello"),
	})
	rst := tcpReset(decode(frame))
	if rst == nil {
		t.Fatal("no reset generated")
	}
	tcp := rst[34 : 34+20]
	if tcp[13] != tcpFlagRST {
		t.Errorf("flags = %#x, want a bare RST for an ACKed segment", tcp[13])
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 9000 {
		t.Errorf("seq = %d, want the peer's ack (9000)", got)
	}
}

func TestTCPResetNotGeneratedForReset(t *testing.T) {
	frame := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "8.8.8.8", proto: protoTCP,
		srcPort: 45000, dstPort: 443, tcpFlags: tcpFlagRST,
	})
	if rst := tcpReset(decode(frame)); rst != nil {
		t.Fatal("answered a RST with a RST")
	}
}

func TestICMPProhibitedForUDP(t *testing.T) {
	frame := udpTo(t, "20.20.20.21", "1.2.3.4", 12345)
	p := decode(frame)

	gw := netip.MustParseAddr("20.20.20.1")
	msg := icmpProhibited(p, gw)
	if msg == nil {
		t.Fatal("no ICMP error generated for a blocked UDP datagram")
	}

	ip := msg[14:34]
	if checksumOver(ip) != 0 {
		t.Error("IPv4 header checksum is wrong")
	}
	if ip[9] != protoICMP {
		t.Errorf("protocol = %d, want ICMP", ip[9])
	}
	if got := netip.AddrFrom4([4]byte(ip[12:16])).String(); got != "20.20.20.1" {
		t.Errorf("ICMP source = %s, want the gateway", got)
	}

	total := int(binary.BigEndian.Uint16(ip[2:4]))
	icmp := msg[34 : 34+total-20]
	if icmp[0] != 3 || icmp[1] != 13 {
		t.Errorf("type/code = %d/%d, want 3/13 (administratively prohibited)", icmp[0], icmp[1])
	}
	if checksumOver(icmp) != 0 {
		t.Error("ICMP checksum is wrong")
	}
	// The quoted datagram must start with the original IP header.
	if !bytes.Equal(icmp[8:8+20], frame[14:34]) {
		t.Error("the ICMP error does not quote the original IP header")
	}
}

func TestICMPv6Prohibited(t *testing.T) {
	frame := buildFrame(t, frameOpts{
		src: "fd00::21", dst: "2001:db8::1", proto: protoUDP,
		srcPort: 45000, dstPort: 9999, payload: []byte("x"),
	})
	p := decode(frame)

	gw := netip.MustParseAddr("fd00::1")
	msg := icmpProhibited(p, gw)
	if msg == nil {
		t.Fatal("no ICMPv6 error generated")
	}
	if et := binary.BigEndian.Uint16(msg[12:14]); et != ethTypeIPv6 {
		t.Fatalf("ethertype = %#x", et)
	}
	hdr := msg[14:54]
	if hdr[6] != protoICMPv6 {
		t.Errorf("next header = %d, want ICMPv6", hdr[6])
	}
	payLen := int(binary.BigEndian.Uint16(hdr[4:6]))
	body := msg[54 : 54+payLen]
	if body[0] != 1 || body[1] != 1 {
		t.Errorf("type/code = %d/%d, want 1/1", body[0], body[1])
	}

	sum := pseudoHeaderSum(gw, netip.MustParseAddr("fd00::21"), protoICMPv6, len(body))
	if finishChecksum(partialChecksum(body, sum)) != 0 {
		t.Error("ICMPv6 checksum is wrong")
	}
}

func TestICMPProhibitedNotGeneratedForICMPErrors(t *testing.T) {
	// An ICMP destination-unreachable (type 3) must not trigger another one.
	frame := buildFrame(t, frameOpts{
		src: "20.20.20.21", dst: "1.2.3.4", proto: protoICMP, payload: []byte{3},
	})
	if msg := icmpProhibited(decode(frame), netip.MustParseAddr("20.20.20.1")); msg != nil {
		t.Fatal("generated an ICMP error in reply to an ICMP error")
	}
}

func TestRejectFallsBackToDestinationWhenGatewayUnset(t *testing.T) {
	frame := udpTo(t, "20.20.20.21", "1.2.3.4", 9)
	msg := icmpProhibited(decode(frame), netip.Addr{})
	if msg == nil {
		t.Fatal("no ICMP error generated")
	}
	if got := netip.AddrFrom4([4]byte(msg[26:30])).String(); got != "1.2.3.4" {
		t.Errorf("ICMP source = %s, want the original destination", got)
	}
}
