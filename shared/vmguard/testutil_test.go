package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	guestMAC = []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	gwMAC    = []byte{0x02, 0x42, 0x0a, 0x0a, 0x0a, 0x01}
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a.Unmap()
}

type frameOpts struct {
	src, dst         string
	proto            uint8
	srcPort, dstPort uint16
	payload          []byte
	tcpFlags         uint8
	tcpSeq, tcpAck   uint32
	vlan             bool
	fragOffset       uint16 // IPv4 fragment offset in 8-byte units
	moreFragments    bool   // set the IPv4 MF flag
	truncateL4       int    // keep only this many bytes of the transport header
	v6ExtHeaders     []byte // raw extension header chain for IPv6
	v6ExtNext        uint8  // first next-header value when v6ExtHeaders is set
}

// buildFrame assembles an Ethernet frame from the guest towards opts.dst.
func buildFrame(t *testing.T, o frameOpts) []byte {
	t.Helper()

	src := mustAddr(t, o.src)
	dst := mustAddr(t, o.dst)

	l4 := buildL4(t, o, src, dst)

	var eth []byte
	eth = append(eth, gwMAC...)
	eth = append(eth, guestMAC...)

	if src.Is4() {
		if o.vlan {
			eth = binary.BigEndian.AppendUint16(eth, ethTypeVLAN)
			eth = binary.BigEndian.AppendUint16(eth, 0x0064)
		}
		eth = binary.BigEndian.AppendUint16(eth, ethTypeIPv4)

		if o.truncateL4 > 0 && o.truncateL4 < len(l4) {
			l4 = l4[:o.truncateL4]
		}

		hdr := make([]byte, 20)
		hdr[0] = 0x45
		binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(l4)))
		flags := o.fragOffset & 0x1fff
		if o.moreFragments {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(hdr[6:8], flags)
		hdr[8] = 64
		hdr[9] = o.proto
		copy(hdr[12:16], src.AsSlice())
		copy(hdr[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(hdr[10:12], checksum(hdr))
		eth = append(eth, hdr...)
		eth = append(eth, l4...)
		return eth
	}

	eth = binary.BigEndian.AppendUint16(eth, ethTypeIPv6)
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(o.v6ExtHeaders)+len(l4)))
	if len(o.v6ExtHeaders) > 0 {
		hdr[6] = o.v6ExtNext
	} else {
		hdr[6] = o.proto
	}
	hdr[7] = 64
	copy(hdr[8:24], src.AsSlice())
	copy(hdr[24:40], dst.AsSlice())
	eth = append(eth, hdr...)
	eth = append(eth, o.v6ExtHeaders...)
	eth = append(eth, l4...)
	return eth
}

func buildL4(t *testing.T, o frameOpts, src, dst netip.Addr) []byte {
	t.Helper()
	switch o.proto {
	case protoTCP:
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:2], o.srcPort)
		binary.BigEndian.PutUint16(tcp[2:4], o.dstPort)
		binary.BigEndian.PutUint32(tcp[4:8], o.tcpSeq)
		binary.BigEndian.PutUint32(tcp[8:12], o.tcpAck)
		tcp[12] = 5 << 4
		tcp[13] = o.tcpFlags
		binary.BigEndian.PutUint16(tcp[14:16], 65535)
		tcp = append(tcp, o.payload...)
		sum := pseudoHeaderSum(src, dst, protoTCP, len(tcp))
		binary.BigEndian.PutUint16(tcp[16:18], finishChecksum(partialChecksum(tcp, sum)))
		return tcp
	case protoUDP:
		udp := make([]byte, 8)
		binary.BigEndian.PutUint16(udp[0:2], o.srcPort)
		binary.BigEndian.PutUint16(udp[2:4], o.dstPort)
		binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(o.payload)))
		udp = append(udp, o.payload...)
		return udp
	case protoICMP, protoICMPv6:
		icmp := make([]byte, 8)
		if len(o.payload) > 0 {
			icmp[0] = o.payload[0]
		} else {
			icmp[0] = 8 // echo request
		}
		return icmp
	}
	return o.payload
}

// tcpSyn is the common case: a guest opening a connection.
func tcpSyn(t *testing.T, src, dst string, port uint16) []byte {
	t.Helper()
	return buildFrame(t, frameOpts{
		src: src, dst: dst, proto: protoTCP,
		srcPort: 45000, dstPort: port,
		tcpFlags: tcpFlagSYN, tcpSeq: 1000,
	})
}

func udpTo(t *testing.T, src, dst string, port uint16) []byte {
	t.Helper()
	return buildFrame(t, frameOpts{
		src: src, dst: dst, proto: protoUDP,
		srcPort: 45000, dstPort: port, payload: []byte("hi"),
	})
}

func testConfig(t *testing.T) *config {
	t.Helper()
	return &config{
		Gateway:   mustAddr(t, "20.20.20.1"),
		Guest:     mustAddr(t, "20.20.20.21"),
		Resolvers: []netip.Addr{mustAddr(t, "20.20.20.1")},
		Reject:    true,
		Stateful:  true,
		LogMode:   logNone,
	}
}

// envMap turns a map into the lookup function buildRules expects.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func buildFilter(t *testing.T, cfg *config, env map[string]string) *filter {
	t.Helper()
	out, in, err := buildRules(cfg, envMap(env))
	if err != nil {
		t.Fatalf("buildRules(%v): %v", env, err)
	}
	return newFilter(cfg, out, in)
}
