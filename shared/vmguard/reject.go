package main

import (
	"encoding/binary"
	"net/netip"
)

// checksum computes the standard internet checksum over b.
func checksum(b []byte) uint16 {
	return finishChecksum(partialChecksum(b, 0))
}

func partialChecksum(b []byte, sum uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pseudoHeaderSum builds the TCP/UDP/ICMPv6 pseudo-header contribution.
func pseudoHeaderSum(src, dst netip.Addr, proto uint8, length int) uint32 {
	var sum uint32
	sum = partialChecksum(src.AsSlice(), sum)
	sum = partialChecksum(dst.AsSlice(), sum)
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

// ethHeader writes an Ethernet header that sends the frame back to the guest.
func ethHeader(out []byte, p *packet, etherType uint16) []byte {
	out = append(out, p.srcMAC()...) // back to the sender
	out = append(out, p.dstMAC()...) // from whoever it was addressed to
	return binary.BigEndian.AppendUint16(out, etherType)
}

// tcpReset synthesises a RST for a blocked TCP segment so the guest fails fast
// instead of retransmitting until its own timeout. It returns nil when a reset
// is not appropriate (already a RST, or no usable transport header).
func tcpReset(p *packet) []byte {
	if p.proto != protoTCP || !p.hasPorts || p.fragment {
		return nil
	}
	if p.tcpFlags&tcpFlagRST != 0 {
		return nil // never answer a reset with a reset
	}

	var seq, ack uint32
	var flags uint8
	if p.tcpFlags&tcpFlagACK != 0 {
		seq = p.tcpAck
		flags = tcpFlagRST
	} else {
		segLen := uint32(p.tcpPayLen)
		if p.tcpFlags&tcpFlagSYN != 0 {
			segLen++
		}
		if p.tcpFlags&tcpFlagFIN != 0 {
			segLen++
		}
		ack = p.tcpSeq + segLen
		flags = tcpFlagRST | tcpFlagACK
	}

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], p.dstPort)
	binary.BigEndian.PutUint16(tcp[2:4], p.srcPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset, no options
	tcp[13] = flags
	// Window 0: the connection is going away immediately.

	sum := pseudoHeaderSum(p.dst, p.src, protoTCP, len(tcp))
	binary.BigEndian.PutUint16(tcp[16:18], finishChecksum(partialChecksum(tcp, sum)))

	if p.v6 {
		return buildIPv6(p, protoTCP, tcp)
	}
	return buildIPv4(p, protoTCP, tcp)
}

// icmpProhibited answers a blocked datagram with "communication administratively
// prohibited" so the guest sees an immediate error rather than a timeout.
func icmpProhibited(p *packet, gateway netip.Addr) []byte {
	if !p.ip || p.proto == protoICMP && !p.v6 && isICMPError(p) {
		return nil
	}

	orig := p.frame[p.l3Off:]

	if p.v6 {
		// ICMPv6 type 1 (destination unreachable) code 1 (administratively
		// prohibited). Include as much of the original packet as fits in the
		// 1280-byte minimum MTU.
		const maxPayload = 1280 - 40 - 8
		if len(orig) > maxPayload {
			orig = orig[:maxPayload]
		}
		body := make([]byte, 8, 8+len(orig))
		body[0] = 1
		body[1] = 1
		body = append(body, orig...)

		src := gateway
		if !src.IsValid() || !src.Is6() {
			src = p.dst
		}
		sum := pseudoHeaderSum(src, p.src, protoICMPv6, len(body))
		binary.BigEndian.PutUint16(body[2:4], finishChecksum(partialChecksum(body, sum)))
		return buildIPv6From(p, src, protoICMPv6, body)
	}

	// ICMPv4 type 3 (destination unreachable) code 13 (communication
	// administratively prohibited), carrying the IP header + 8 bytes.
	n := len(orig)
	if n > 28 {
		n = 28
	}
	body := make([]byte, 8, 8+n)
	body[0] = 3
	body[1] = 13
	body = append(body, orig[:n]...)
	binary.BigEndian.PutUint16(body[2:4], checksum(body))

	src := gateway
	if !src.IsValid() || !src.Is4() {
		src = p.dst
	}
	return buildIPv4From(p, src, protoICMP, body)
}

// isICMPError avoids generating an error in reply to an ICMP error message.
func isICMPError(p *packet) bool {
	if p.l4Off == 0 || p.l4Off >= len(p.frame) {
		return false
	}
	switch p.frame[p.l4Off] {
	case 3, 4, 5, 11, 12:
		return true
	}
	return false
}

func buildIPv4(p *packet, proto uint8, payload []byte) []byte {
	return buildIPv4From(p, p.dst, proto, payload)
}

func buildIPv4From(p *packet, src netip.Addr, proto uint8, payload []byte) []byte {
	if !src.Is4() || !p.src.Is4() {
		return nil
	}
	out := make([]byte, 0, 14+20+len(payload))
	out = ethHeader(out, p, ethTypeIPv4)

	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(payload)))
	hdr[8] = 64 // TTL
	hdr[9] = proto
	copy(hdr[12:16], src.AsSlice())
	copy(hdr[16:20], p.src.AsSlice())
	binary.BigEndian.PutUint16(hdr[10:12], checksum(hdr))

	out = append(out, hdr...)
	out = append(out, payload...)
	return pad(out)
}

func buildIPv6(p *packet, proto uint8, payload []byte) []byte {
	return buildIPv6From(p, p.dst, proto, payload)
}

func buildIPv6From(p *packet, src netip.Addr, proto uint8, payload []byte) []byte {
	if !src.Is6() || !p.src.Is6() {
		return nil
	}
	out := make([]byte, 0, 14+40+len(payload))
	out = ethHeader(out, p, ethTypeIPv6)

	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)))
	hdr[6] = proto
	hdr[7] = 64 // hop limit
	copy(hdr[8:24], src.AsSlice())
	copy(hdr[24:40], p.src.AsSlice())

	out = append(out, hdr...)
	out = append(out, payload...)
	return pad(out)
}

// pad extends a frame to the 60-byte Ethernet minimum, matching what passt and
// real NICs put on the wire.
func pad(frame []byte) []byte {
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame
}
