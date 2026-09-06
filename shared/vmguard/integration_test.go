//go:build integration

// These tests run vmguard against the real passt binary and assert that a
// synthetic guest — one that speaks the same qemu socket protocol QEMU does —
// can and cannot reach a real TCP listener according to the policy.
//
// They need passt on PATH, so they are excluded from the default build:
//
//	go test -tags integration ./...
//
// The repository's CI runs them inside the qemux/qemu image, which ships passt.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	guestIP   = "20.20.20.21"
	gatewayIP = "20.20.20.1"
)

var gatewayMAC = []byte{0x02, 0x42, 0x0a, 0x0a, 0x0a, 0x01}

func requirePasst(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("passt")
	if err != nil {
		t.Skip("passt is not installed; skipping the integration test")
	}
	return path
}

// startPasst launches a real passt and returns its socket path.
func startPasst(t *testing.T, dir string) string {
	t.Helper()

	bin := requirePasst(t)
	sock := filepath.Join(dir, "passt.sock")
	pidFile := filepath.Join(dir, "passt.pid")
	logFile := filepath.Join(dir, "passt.log")

	// passt daemonises itself, so the command returns once it is listening.
	cmd := exec.Command(bin,
		"-4",
		"-a", guestIP,
		"-g", gatewayIP,
		"-n", "255.255.255.0",
		"-m", "1500",
		"-M", "02:42:0a:0a:0a:01",
		"-P", pidFile,
		"-s", sock,
		"-l", logFile,
		"-q",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("passt failed to start: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(string(trimSpace(data))); err == nil {
				_ = exec.Command("kill", strconv.Itoa(pid)).Run()
			}
		}
		if data, err := os.ReadFile(logFile); err == nil && t.Failed() {
			t.Logf("passt log:\n%s", data)
		}
	})

	return sock
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// startListener runs a TCP server on the loopback interface. passt maps the
// gateway address to the host's loopback, so the guest reaches it by dialling
// gatewayIP on the same port.
func startListener(t *testing.T) (port int, accepted chan struct{}) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted = make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			c.Close()
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port, accepted
}

// syntheticGuest speaks the qemu socket protocol the way QEMU's stream netdev
// does, so passt cannot tell it apart from a real guest.
type syntheticGuest struct {
	fc *frameConn
}

func dialGuest(t *testing.T, sock string) *syntheticGuest {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}
	t.Cleanup(func() { c.Close() })
	return &syntheticGuest{fc: newFrameConn(c)}
}

// syn sends a TCP SYN towards dst:port from the guest address.
func (g *syntheticGuest) syn(t *testing.T, dst string, port uint16, srcPort uint16) {
	t.Helper()
	frame := buildFrame(t, frameOpts{
		src: guestIP, dst: dst, proto: protoTCP,
		srcPort: srcPort, dstPort: port,
		tcpFlags: tcpFlagSYN, tcpSeq: 1000,
	})
	// Address the frame to the gateway MAC, as a real guest would.
	copy(frame[0:6], gatewayMAC)
	if err := g.fc.write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// awaitTCP waits for the first TCP segment addressed to srcPort and returns it.
func (g *syntheticGuest) awaitTCP(t *testing.T, srcPort uint16, within time.Duration) *packet {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		g.fc.c.SetReadDeadline(deadline)
		frame, err := g.fc.read(nil)
		if err != nil {
			return nil
		}
		p := decode(frame)
		if p.ip && p.proto == protoTCP && p.dstPort == srcPort {
			return p
		}
	}
	return nil
}

// startRelay runs vmguard between the synthetic guest and passt.
func startRelay(t *testing.T, dir, passtSock string, env map[string]string) (string, *filter) {
	t.Helper()

	cfg := testConfig(t)
	cfg.Gateway = mustAddr(t, gatewayIP)
	cfg.Guest = mustAddr(t, guestIP)
	cfg.Resolvers = nil
	cfg.Listen = filepath.Join(dir, "guard.sock")
	cfg.Upstream = passtSock

	f := buildFilter(t, cfg, env)
	go func() {
		if err := run(cfg, f); err != nil {
			t.Logf("relay stopped: %v", err)
		}
	}()

	for i := 0; i < 200; i++ {
		if _, err := os.Stat(cfg.Listen); err == nil {
			return cfg.Listen, f
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("vmguard never created its socket")
	return "", nil
}

func TestIntegrationAllowedConnectionReachesTheListener(t *testing.T) {
	requirePasst(t)
	dir := t.TempDir()

	port, accepted := startListener(t)
	passtSock := startPasst(t, dir)
	guardSock, _ := startRelay(t, dir, passtSock, map[string]string{
		"NET_ALLOW": fmt.Sprintf("tcp:%s:%d", gatewayIP, port),
	})

	g := dialGuest(t, guardSock)
	g.syn(t, gatewayIP, uint16(port), 45001)

	reply := g.awaitTCP(t, 45001, 5*time.Second)
	if reply == nil {
		t.Fatal("no answer to the SYN")
	}
	if reply.tcpFlags&tcpFlagSYN == 0 || reply.tcpFlags&tcpFlagACK == 0 {
		t.Fatalf("expected SYN-ACK from passt, got flags %#x", reply.tcpFlags)
	}

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("passt never opened the real connection to the listener")
	}
}

func TestIntegrationBlockedConnectionIsResetAndNeverReachesTheListener(t *testing.T) {
	requirePasst(t)
	dir := t.TempDir()

	port, accepted := startListener(t)
	passtSock := startPasst(t, dir)
	guardSock, _ := startRelay(t, dir, passtSock, map[string]string{
		"NET_DENY": fmt.Sprintf("tcp:%s:%d", gatewayIP, port),
	})

	g := dialGuest(t, guardSock)
	g.syn(t, gatewayIP, uint16(port), 45002)

	reply := g.awaitTCP(t, 45002, 5*time.Second)
	if reply == nil {
		t.Fatal("no reset came back for a blocked connection")
	}
	if reply.tcpFlags&tcpFlagRST == 0 {
		t.Fatalf("expected a RST, got flags %#x", reply.tcpFlags)
	}

	select {
	case <-accepted:
		t.Fatal("a blocked connection reached the listener")
	case <-time.After(1500 * time.Millisecond):
	}
}

func TestIntegrationDefaultDenyStillAllowsDNSToTheGateway(t *testing.T) {
	requirePasst(t)
	dir := t.TempDir()

	passtSock := startPasst(t, dir)
	guardSock, f := startRelay(t, dir, passtSock, map[string]string{"NET_PRESET": "isolated"})

	g := dialGuest(t, guardSock)

	// A DNS query to the gateway must survive a deny-all policy. Whether an
	// answer comes back depends on the sandbox's own resolver, so the assertion
	// is that the guard forwarded the query rather than blocking it.
	frame := buildFrame(t, frameOpts{
		src: guestIP, dst: gatewayIP, proto: protoUDP,
		srcPort: 45003, dstPort: 53, payload: dnsQuery("example.com"),
	})
	copy(frame[0:6], gatewayMAC)
	if err := g.fc.write(frame); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)

	if n := f.stats.deniedOut.Load(); n != 0 {
		t.Fatalf("DNS to the gateway was blocked (%d denied) under an isolated policy", n)
	}
	if n := f.stats.framesOut.Load(); n == 0 {
		t.Fatal("the guard never saw the query")
	}
}

func TestIntegrationBlockedUDPGetsAnICMPError(t *testing.T) {
	requirePasst(t)
	dir := t.TempDir()

	passtSock := startPasst(t, dir)
	guardSock, f := startRelay(t, dir, passtSock, map[string]string{"NET_PRESET": "isolated"})

	g := dialGuest(t, guardSock)

	frame := buildFrame(t, frameOpts{
		src: guestIP, dst: "8.8.8.8", proto: protoUDP,
		srcPort: 45004, dstPort: 12345, payload: []byte("blocked"),
	})
	copy(frame[0:6], gatewayMAC)
	if err := g.fc.write(frame); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	g.fc.c.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		raw, err := g.fc.read(nil)
		if err != nil {
			break
		}
		p := decode(raw)
		if !p.ip || p.proto != protoICMP || p.l4Off == 0 {
			continue
		}
		if p.frame[p.l4Off] == 3 && p.frame[p.l4Off+1] == 13 {
			if f.stats.rejectsICM.Load() != 1 {
				t.Errorf("rejectsICM = %d, want 1", f.stats.rejectsICM.Load())
			}
			return
		}
	}
	t.Fatal("no administratively-prohibited ICMP error came back")
}

// dnsQuery builds a minimal A query so passt has something well-formed to relay.
func dnsQuery(name string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)      // one question

	label := []byte{}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label = append(label, byte(i-start))
			label = append(label, name[start:i]...)
			start = i + 1
		}
	}
	label = append(label, 0)

	msg = append(msg, label...)
	msg = binary.BigEndian.AppendUint16(msg, 1) // A
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	return msg
}
