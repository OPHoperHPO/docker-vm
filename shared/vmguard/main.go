// Command vmguard enforces a network access policy on a QEMU guest from
// outside the guest.
//
// The qemux/qemu image runs the guest's network through passt, a userspace
// network stack: QEMU connects to a unix socket and exchanges raw Ethernet
// frames with it, framed as a 4-byte big-endian length followed by the frame.
// vmguard interposes on that socket. QEMU connects to vmguard, vmguard connects
// to passt, and every frame is decoded and matched against an ACL before it is
// forwarded.
//
// That placement is what makes the policy trustworthy: it needs no capabilities
// on the host, it does not touch host firewall state shared with other
// containers, and nothing inside the guest — including root — can reach or
// change it.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// maxFrame bounds a single Ethernet frame. passt refuses to send more than
// 64 KiB and QEMU's stream backend uses the same limit.
const maxFrame = 65535

func main() {
	var (
		listenPath = flag.String("listen", "", "unix socket to create for QEMU to connect to")
		upstream   = flag.String("upstream", "", "unix socket where passt is listening")
		gatewayStr = flag.String("gateway", "", "address of the gateway passt presents to the guest")
		guestStr   = flag.String("guest", "", "address passt assigns to the guest")
		resolvConf = flag.String("resolv", "/etc/resolv.conf", "resolver file used to expand the 'dns' alias")
		checkOnly  = flag.Bool("check", false, "parse the configuration, print it and exit")
	)
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("[vmguard] ")

	cfg := &config{
		Listen:    *listenPath,
		Upstream:  *upstream,
		Strict:    truthy(envOr("NET_GUARD_STRICT", "N")),
		Stateful:  !falsy(envOr("NET_GUARD_STATEFUL", "Y")),
		Reject:    !falsy(envOr("NET_GUARD_REJECT", "Y")),
		LogMode:   parseLogMode(envOr("NET_GUARD_LOG", "blocked")),
		HTTPAddr:  envOr("NET_GUARD_HTTP", ""),
		RulesFile: envOr("NET_RULES_FILE", ""),
		Resolvers: readResolvers(*resolvConf),
	}

	if v := envOr("NET_RESOLVE_INTERVAL", "60s"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("invalid NET_RESOLVE_INTERVAL %q: %v", v, err)
		}
		cfg.Resolve = d
	}
	if cfg.Resolve < 5*time.Second {
		cfg.Resolve = 5 * time.Second
	}

	if a, err := netip.ParseAddr(*gatewayStr); err == nil {
		cfg.Gateway = a.Unmap()
	}
	if a, err := netip.ParseAddr(*guestStr); err == nil {
		cfg.Guest = a.Unmap()
	}

	out, in, err := buildRules(cfg, os.Getenv)
	if err != nil {
		log.Fatalf("invalid network rules: %v", err)
	}

	f := newFilter(cfg, out, in)

	res := &hostResolver{lookup: lookupHost, targets: append(out.hostRules(), in.hostRules()...)}
	if len(res.targets) > 0 {
		res.refresh()
	}

	for _, line := range describe(cfg, out, in) {
		log.Print(line)
	}

	if *checkOnly {
		return
	}
	if cfg.Listen == "" || cfg.Upstream == "" {
		log.Fatal("both -listen and -upstream are required")
	}

	if cfg.HTTPAddr != "" {
		go serveStatus(cfg, f)
	}
	go watchRules(cfg, f, res, 2*time.Second)
	if len(res.targets) > 0 {
		go func() {
			t := time.NewTicker(cfg.Resolve)
			defer t.Stop()
			for range t.C {
				res.refresh()
			}
		}()
	}

	if err := run(cfg, f); err != nil {
		log.Fatal(err)
	}
}

func lookupHost(host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(nil, "ip", host)
}

// run creates the guest-facing socket and relays every accepted connection.
func run(cfg *config, f *filter) error {
	if err := os.Remove(cfg.Listen); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket %s: %w", cfg.Listen, err)
	}

	ln, err := net.Listen("unix", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	defer ln.Close()

	// QEMU runs unprivileged in some configurations; keep the socket reachable.
	if err := os.Chmod(cfg.Listen, 0o666); err != nil {
		log.Printf("warning: chmod %s: %v", cfg.Listen, err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		ln.Close()
	}()

	log.Printf("ready, waiting for QEMU on %s", cfg.Listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go handle(conn, cfg, f)
	}
}

// frameConn serialises writes so relayed frames and synthesised rejects cannot
// interleave inside a single length-prefixed frame.
type frameConn struct {
	c  net.Conn
	r  *bufio.Reader
	mu sync.Mutex
}

func newFrameConn(c net.Conn) *frameConn {
	return &frameConn{c: c, r: bufio.NewReaderSize(c, 1<<16)}
}

func (fc *frameConn) read(buf []byte) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(fc.r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return buf[:0], nil
	}
	if n > maxFrame {
		return nil, fmt.Errorf("frame of %d bytes exceeds the %d byte maximum", n, maxFrame)
	}
	if cap(buf) < int(n) {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(fc.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (fc *frameConn) write(frame []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))

	fc.mu.Lock()
	defer fc.mu.Unlock()
	bufs := net.Buffers{hdr[:], frame}
	_, err := bufs.WriteTo(fc.c)
	return err
}

func handle(raw net.Conn, cfg *config, f *filter) {
	defer raw.Close()

	up, err := net.Dial("unix", cfg.Upstream)
	if err != nil {
		log.Printf("cannot reach passt on %s: %v", cfg.Upstream, err)
		return
	}
	defer up.Close()

	guest := newFrameConn(raw)
	world := newFrameConn(up)

	log.Printf("QEMU connected; filtering traffic")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer up.Close()
		defer raw.Close()
		pump(guest, world, guest, cfg, f, egress)
	}()
	go func() {
		defer wg.Done()
		defer up.Close()
		defer raw.Close()
		pump(world, guest, guest, cfg, f, ingress)
	}()
	wg.Wait()

	log.Printf("QEMU disconnected")
}

// pump moves frames from src to dst, dropping the ones the ACL rejects.
// reply is always the guest-facing connection: that is where a synthesised
// RST or ICMP error has to go.
func pump(src, dst, reply *frameConn, cfg *config, f *filter, dir direction) {
	buf := make([]byte, 0, 2048)
	for {
		frame, err := src.read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) &&
				!errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Printf("%s stream ended: %v", dir, err)
			}
			return
		}
		buf = frame[:0]

		if dir == egress {
			f.stats.framesOut.Add(1)
			f.stats.bytesOut.Add(uint64(len(frame)))
		} else {
			f.stats.framesIn.Add(1)
			f.stats.bytesIn.Add(uint64(len(frame)))
		}

		p := decode(frame)
		v := f.inspect(p, dir)

		if v.act == actionDeny {
			if line := f.note(p, dir, v, time.Now()); line != "" {
				log.Print(line)
			}
			if cfg.Reject && dir == egress {
				sendReject(reply, p, cfg, f)
			}
			continue
		}

		if f.cfg.LogMode == logAll && p.ip {
			log.Printf("allowed %s %s %s -> %s", dir, p.protoName(), p.src, p.dst)
		}

		if err := dst.write(frame); err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.EPIPE) {
				log.Printf("%s forward failed: %v", dir, err)
			}
			return
		}
	}
}

// sendReject tells the guest immediately that a flow was refused.
func sendReject(reply *frameConn, p *packet, cfg *config, f *filter) {
	if !p.ip {
		return
	}
	if p.proto == protoTCP {
		if rst := tcpReset(p); rst != nil {
			if err := reply.write(rst); err == nil {
				f.stats.rejectsTCP.Add(1)
			}
		}
		return
	}
	if icmp := icmpProhibited(p, cfg.Gateway); icmp != nil {
		if err := reply.write(icmp); err == nil {
			f.stats.rejectsICM.Add(1)
		}
	}
}
