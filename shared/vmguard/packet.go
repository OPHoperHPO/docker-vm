package main

import (
	"encoding/binary"
	"net/netip"
)

// Ethernet / IP constants used while decoding guest frames.
const (
	ethTypeIPv4 = 0x0800
	ethTypeARP  = 0x0806
	ethTypeIPv6 = 0x86dd
	ethTypeVLAN = 0x8100
	ethTypeQinQ = 0x88a8

	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

// packet is the decoded view of a single Ethernet frame. Only the fields the
// filter and the reject synthesiser need are extracted; the frame itself is
// never copied.
type packet struct {
	frame []byte

	etherType uint16 // innermost ethertype (VLAN tags already skipped)
	l3Off     int    // offset of the IP header inside frame
	l4Off     int    // offset of the transport header, 0 when unavailable

	ip        bool // frame carries IPv4 or IPv6
	v6        bool
	malformed bool // an IP ethertype whose headers could not be resolved
	src, dst  netip.Addr

	proto     uint8
	hasPorts  bool // transport header was present and complete
	srcPort   uint16
	dstPort   uint16
	fragment  bool // non-first fragment: ports are not available
	moreFrags bool // this datagram continues in a later fragment
	tcpFlags  uint8
	tcpSeq    uint32
	tcpAck    uint32
	tcpPayLen int
}

// srcMAC and dstMAC return the Ethernet addresses of the frame. Frames shorter
// than a full Ethernet header never reach here.
func (p *packet) dstMAC() []byte { return p.frame[0:6] }
func (p *packet) srcMAC() []byte { return p.frame[6:12] }

// decode parses an Ethernet frame far enough to make a filtering decision.
// A frame that cannot be decoded is returned with ip == false, which the
// filter treats as "not an IP packet" (ARP, LLDP, ...).
func decode(frame []byte) *packet {
	p := &packet{frame: frame}
	if len(frame) < 14 {
		return p
	}

	off := 12
	et := binary.BigEndian.Uint16(frame[off : off+2])
	off += 2

	// Skip up to two stacked VLAN tags.
	for i := 0; i < 2; i++ {
		if et != ethTypeVLAN && et != ethTypeQinQ {
			break
		}
		if len(frame) < off+4 {
			return p
		}
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}

	p.etherType = et
	p.l3Off = off

	switch et {
	case ethTypeIPv4:
		p.decodeIPv4()
	case ethTypeIPv6:
		p.decodeIPv6()
	}
	return p
}

func (p *packet) decodeIPv4() {
	b := p.frame[p.l3Off:]
	if len(b) < 20 {
		p.malformed = true
		return
	}

	// The version nibble is deliberately not checked. passt dispatches on the
	// ethertype alone and never looks at it, so refusing to decode a packet
	// whose nibble says something other than 4 would leave vmguard blind to a
	// frame passt still treats as ordinary IPv4.
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		p.malformed = true
		return
	}

	p.ip = true
	p.src = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	p.dst = netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]})
	p.proto = b[9]

	// Total length may be smaller than the (padded) frame; clamp so payload
	// length arithmetic for the RST we synthesise stays correct.
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		total = len(b)
	}

	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	p.moreFrags = flagsFrag&0x2000 != 0
	if flagsFrag&0x1fff != 0 {
		p.fragment = true
		return
	}

	p.l4Off = p.l3Off + ihl
	p.decodeTransport(total - ihl)
}

func (p *packet) decodeIPv6() {
	b := p.frame[p.l3Off:]
	if len(b) < 40 {
		p.malformed = true
		return
	}

	// As in decodeIPv4: the ethertype already chose the family, and passt does
	// not check the version nibble either.

	p.ip = true
	p.v6 = true
	p.src, _ = netip.AddrFromSlice(b[8:24])
	p.dst, _ = netip.AddrFromSlice(b[24:40])

	payLen := int(binary.BigEndian.Uint16(b[4:6]))
	if payLen == 0 || payLen > len(b)-40 {
		payLen = len(b) - 40
	}

	next := b[6]
	off := 40
	end := 40 + payLen

	// Walk the extension header chain to reach the transport header.
	//
	// Only the headers where this walk and passt's agree byte for byte are
	// followed. passt treats a wider set as extension headers (its
	// IPV6_NH_OPT covers 50, 51, 139, 140, 253 and 254 as well) and advances
	// over all of them with the same length rule, which does not match how
	// those headers are actually encoded. Rather than guess which of the two
	// readings a packet will get, a chain containing one of them is refused:
	// the alternative is a packet whose ports vmguard reads from one offset
	// and passt from another.
	for i := 0; i < 16; i++ {
		switch next {
		case 0, 43, 60, 135: // hop-by-hop, routing, destination options, mobility
			if off+2 > len(b) {
				p.malformed = true
				return
			}
			hdrLen := (int(b[off+1]) + 1) * 8
			next = b[off]
			off += hdrLen
		case 44: // fragment header
			if off+8 > len(b) {
				p.malformed = true
				return
			}
			fragField := binary.BigEndian.Uint16(b[off+2 : off+4])
			p.moreFrags = fragField&0x0001 != 0
			next = b[off]
			off += 8
			if fragField&^0x0007 != 0 {
				p.proto = next
				p.fragment = true
				return
			}
		case 50, 51, 139, 140, 253, 254: // read differently by passt
			p.malformed = true
			return
		case 59: // no next header: nothing follows, judge it by address
			p.proto = next
			return
		default:
			p.proto = next
			if off > len(b) || off >= end {
				p.malformed = true
				return
			}
			p.l4Off = p.l3Off + off
			p.decodeTransport(end - off)
			return
		}
		if off >= len(b) {
			p.malformed = true
			return
		}
	}

	// A chain this long is not something a real stack produces, and passt walks
	// it without a limit; stopping here without a verdict would be a blind spot.
	p.malformed = true
}

// decodeTransport reads ports (and TCP state needed for a RST) from the
// transport header at p.l4Off. l4Len is the transport length according to the
// IP header, used to derive the TCP payload length.
func (p *packet) decodeTransport(l4Len int) {
	b := p.frame[p.l4Off:]
	if l4Len < 0 || l4Len > len(b) {
		l4Len = len(b)
	}

	switch p.proto {
	case protoTCP:
		if l4Len < 20 {
			return
		}
		p.hasPorts = true
		p.srcPort = binary.BigEndian.Uint16(b[0:2])
		p.dstPort = binary.BigEndian.Uint16(b[2:4])
		p.tcpSeq = binary.BigEndian.Uint32(b[4:8])
		p.tcpAck = binary.BigEndian.Uint32(b[8:12])
		p.tcpFlags = b[13]
		dataOff := int(b[12]>>4) * 4
		if dataOff < 20 || dataOff > l4Len {
			dataOff = 20
		}
		p.tcpPayLen = l4Len - dataOff
	case protoUDP:
		if l4Len < 8 {
			return
		}
		p.hasPorts = true
		p.srcPort = binary.BigEndian.Uint16(b[0:2])
		p.dstPort = binary.BigEndian.Uint16(b[2:4])
	}
}

// truncatedFirstFragment reports a first fragment that does not carry its own
// transport header.
//
// The smallest IPv4 path MTU leaves room for far more than a TCP or UDP header,
// so no real stack emits one; it is a long-standing way to hide the port a
// firewall rule matches on and let the receiver reassemble the real one.
func (p *packet) truncatedFirstFragment() bool {
	if !p.ip || !p.moreFrags || p.fragment {
		return false
	}
	switch p.proto {
	case protoTCP, protoUDP:
		return !p.hasPorts
	}
	return false
}

// protoName renders the IP protocol for rules and log lines.
func (p *packet) protoName() string {
	switch p.proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP, protoICMPv6:
		return "icmp"
	}
	return "ip"
}
