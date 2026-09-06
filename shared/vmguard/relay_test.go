package main

import (
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// fakePasst stands in for the real passt process: it accepts one connection and
// records every frame it is handed.
type fakePasst struct {
	ln     net.Listener
	frames chan []byte
	ready  chan struct{}
	conn   net.Conn // valid once ready is closed
}

func startFakePasst(t *testing.T, path string) *fakePasst {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	fp := &fakePasst{ln: ln, frames: make(chan []byte, 64), ready: make(chan struct{})}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		fp.conn = c
		close(fp.ready)
		fc := newFrameConn(c)
		buf := make([]byte, 0, 2048)
		for {
			frame, err := fc.read(buf)
			if err != nil {
				close(fp.frames)
				return
			}
			cp := append([]byte(nil), frame...)
			buf = frame[:0]
			fp.frames <- cp
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return fp
}

func (fp *fakePasst) next(t *testing.T, within time.Duration) []byte {
	t.Helper()
	select {
	case f, ok := <-fp.frames:
		if !ok {
			t.Fatal("passt side closed")
		}
		return f
	case <-time.After(within):
		return nil
	}
}

// startGuard runs the relay for the duration of the test and returns the
// guest-facing connection plus the filter, so counters can be asserted.
func startGuard(t *testing.T, env map[string]string) (*frameConn, *fakePasst, *filter) {
	t.Helper()

	dir := t.TempDir()
	passtPath := filepath.Join(dir, "passt.sock")
	guardPath := filepath.Join(dir, "guard.sock")

	fp := startFakePasst(t, passtPath)

	cfg := testConfig(t)
	cfg.Listen = guardPath
	cfg.Upstream = passtPath

	f := buildFilter(t, cfg, env)

	done := make(chan error, 1)
	go func() { done <- run(cfg, f) }()

	// Wait for the guard's socket to appear.
	var qemu net.Conn
	var err error
	for i := 0; i < 200; i++ {
		qemu, err = net.Dial("unix", guardPath)
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("QEMU could not connect to the guard: %v", err)
	}
	t.Cleanup(func() { qemu.Close() })

	select {
	case <-fp.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("the guard never connected to passt")
	}

	return newFrameConn(qemu), fp, f
}

func TestRelayForwardsAllowedTraffic(t *testing.T) {
	qemu, passt, _ := startGuard(t, nil)

	frame := tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)
	if err := qemu.write(frame); err != nil {
		t.Fatal(err)
	}

	got := passt.next(t, 2*time.Second)
	if got == nil {
		t.Fatal("allowed frame never reached passt")
	}
	if string(got) != string(frame) {
		t.Error("the forwarded frame was modified")
	}
}

func TestRelayBlocksAndResets(t *testing.T) {
	qemu, passt, f := startGuard(t, map[string]string{"NET_DENY": "10.0.0.0/8"})

	blocked := tcpSyn(t, "20.20.20.21", "10.1.2.3", 22)
	if err := qemu.write(blocked); err != nil {
		t.Fatal(err)
	}

	// The guest gets an immediate reset...
	qemu.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := qemu.read(nil)
	if err != nil {
		t.Fatalf("no reset came back: %v", err)
	}
	p := decode(reply)
	if p.proto != protoTCP || p.tcpFlags&tcpFlagRST == 0 {
		t.Fatalf("reply was not a TCP reset: proto=%d flags=%#x", p.proto, p.tcpFlags)
	}
	if p.src.String() != "10.1.2.3" || p.dst.String() != "20.20.20.21" {
		t.Errorf("reset addressed %s -> %s", p.src, p.dst)
	}

	// ...and passt never sees the frame.
	if extra := passt.next(t, 300*time.Millisecond); extra != nil {
		t.Errorf("a blocked frame reached passt: %x", extra[:14])
	}

	if f.stats.deniedOut.Load() != 1 {
		t.Errorf("deniedOut = %d, want 1", f.stats.deniedOut.Load())
	}
	if f.stats.rejectsTCP.Load() != 1 {
		t.Errorf("rejectsTCP = %d, want 1", f.stats.rejectsTCP.Load())
	}
}

func TestRelayDropsSilentlyWhenRejectDisabled(t *testing.T) {
	dir := t.TempDir()
	passtPath := filepath.Join(dir, "passt.sock")
	guardPath := filepath.Join(dir, "guard.sock")
	fp := startFakePasst(t, passtPath)

	cfg := testConfig(t)
	cfg.Listen, cfg.Upstream = guardPath, passtPath
	cfg.Reject = false
	f := buildFilter(t, cfg, map[string]string{"NET_DENY": "10.0.0.0/8"})
	go run(cfg, f)

	var qemu net.Conn
	var err error
	for i := 0; i < 200; i++ {
		if qemu, err = net.Dial("unix", guardPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer qemu.Close()
	<-fp.ready

	fc := newFrameConn(qemu)
	if err := fc.write(tcpSyn(t, "20.20.20.21", "10.1.2.3", 22)); err != nil {
		t.Fatal(err)
	}

	qemu.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := fc.read(nil); err == nil {
		t.Fatal("a reset was sent even though NET_GUARD_REJECT is off")
	}
	if f.stats.rejectsTCP.Load() != 0 {
		t.Errorf("rejectsTCP = %d, want 0", f.stats.rejectsTCP.Load())
	}
}

func TestRelayPassesReturnTraffic(t *testing.T) {
	qemu, passt, _ := startGuard(t, nil)

	// Push a frame out so the fake passt hands us its connection.
	if err := qemu.write(tcpSyn(t, "20.20.20.21", "8.8.8.8", 443)); err != nil {
		t.Fatal(err)
	}
	if passt.next(t, 2*time.Second) == nil {
		t.Fatal("egress frame never arrived")
	}

	inbound := buildFrame(t, frameOpts{
		src: "8.8.8.8", dst: "20.20.20.21", proto: protoTCP,
		srcPort: 443, dstPort: 45000, tcpFlags: tcpFlagSYN | tcpFlagACK,
	})

	// Write from the passt side back towards the guest.
	if err := newFrameConn(passt.conn).write(inbound); err != nil {
		t.Fatal(err)
	}

	qemu.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := qemu.read(nil)
	if err != nil {
		t.Fatalf("return traffic never reached the guest: %v", err)
	}
	if string(got) != string(inbound) {
		t.Error("the inbound frame was modified")
	}
}

func TestFrameConnRejectsOversizedFrames(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], maxFrame+1)
		client.Write(hdr[:])
	}()

	fc := newFrameConn(server)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := fc.read(nil); err == nil {
		t.Fatal("an oversized length header was accepted")
	}
}

func TestFrameConnRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 1500)
	for i := range payload {
		payload[i] = byte(i)
	}

	go func() { newFrameConn(client).write(payload) }()

	fc := newFrameConn(server)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := fc.read(nil)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round trip changed the frame (%d bytes back, %d out)", len(got), len(payload))
	}
}
