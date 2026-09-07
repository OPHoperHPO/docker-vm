package main

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Connection tracking makes the ACL a policy about who may *start* talking to
// whom, which is what firewall rules are normally understood to mean.
//
// Without it a rule like "deny private" also kills the guest's replies to
// connections forwarded into it, because the peer of an inbound SSH session is
// a private address like the container gateway. Recording a flow when it is
// first allowed, and letting both directions of that flow through afterwards,
// removes that surprise without weakening the policy: a flow can only ever be
// recorded by a packet the rules already permitted.
const (
	defaultFlowCap = 1 << 16

	tcpIdleTimeout   = time.Hour
	otherIdleTimeout = 2 * time.Minute
	sweepInterval    = 30 * time.Second
)

// flowKey identifies a conversation independently of which way a packet is
// travelling: the guest side and the peer side are stored in fixed slots.
type flowKey struct {
	proto     uint8
	peer      netip.Addr
	peerPort  uint16
	local     netip.Addr
	localPort uint16
}

func keyFor(p *packet, dir direction) flowKey {
	k := flowKey{proto: p.proto}
	if dir == egress {
		k.peer, k.peerPort = p.dst, p.dstPort
		k.local, k.localPort = p.src, p.srcPort
	} else {
		k.peer, k.peerPort = p.src, p.srcPort
		k.local, k.localPort = p.dst, p.dstPort
	}
	if !p.hasPorts {
		k.peerPort, k.localPort = 0, 0
	}
	return k
}

type conntrack struct {
	mu        sync.Mutex
	flows     map[flowKey]time.Time
	cap       int
	lastSweep time.Time
}

func newConntrack(capacity int) *conntrack {
	if capacity <= 0 {
		capacity = defaultFlowCap
	}
	return &conntrack{flows: make(map[flowKey]time.Time), cap: capacity}
}

// seen reports whether the flow is already established, refreshing it when so.
func (c *conntrack) seen(k flowKey, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.flows[k]; !ok {
		return false
	}
	c.flows[k] = now
	return true
}

// record remembers a flow that the policy allowed.
func (c *conntrack) record(k flowKey, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.flows[k] = now

	if len(c.flows) > c.cap || now.Sub(c.lastSweep) > sweepInterval {
		c.sweepLocked(now)
	}
}

// forget drops a flow that has been torn down.
func (c *conntrack) forget(k flowKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.flows, k)
}

// reset drops every tracked flow. It runs when the rules change so that a
// tightened policy takes effect immediately instead of letting connections that
// the old rules permitted continue indefinitely.
func (c *conntrack) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flows = make(map[flowKey]time.Time)
}

func (c *conntrack) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.flows)
}

// sweepLocked drops idle flows, then the oldest ones if the table is still over
// its cap. Evicting by last-seen keeps busy connections alive under pressure.
func (c *conntrack) sweepLocked(now time.Time) {
	c.lastSweep = now

	for k, last := range c.flows {
		timeout := otherIdleTimeout
		if k.proto == protoTCP {
			timeout = tcpIdleTimeout
		}
		if now.Sub(last) > timeout {
			delete(c.flows, k)
		}
	}

	if len(c.flows) <= c.cap {
		return
	}

	type aged struct {
		key  flowKey
		last time.Time
	}
	all := make([]aged, 0, len(c.flows))
	for k, last := range c.flows {
		all = append(all, aged{k, last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })

	for _, a := range all[:len(c.flows)-c.cap] {
		delete(c.flows, a.key)
	}
}

// tearsDown reports whether this packet ends the conversation, so the entry can
// be released instead of waiting out the idle timeout.
func tearsDown(p *packet) bool {
	return p.proto == protoTCP && p.tcpFlags&tcpFlagRST != 0
}
