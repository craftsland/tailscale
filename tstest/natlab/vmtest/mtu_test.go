// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// runUnfixedTests gates tests that reproduce a known, still-unfixed defect.
// They are expected to fail until it is fixed, so they don't run in CI (which
// discovers and runs every Test* in this package); the flag keeps them one
// command away locally.
var runUnfixedTests = flag.Bool("run-unfixed-tests", false,
	"run tests that reproduce known-unfixed bugs and are expected to fail")

// underlayMTU is the WAN MTU we impose on the path between the two nodes: the
// MTU of a Tailscale TUN, i.e. what the underlay would be if this tailnet ran
// over another one.
const underlayMTU = 1280

// bulkTimeout bounds the test side of a bulk transfer. TTA caps its own
// upstream fetch at 10s (see [vmtest.Env.HTTPGetN]), so this is deliberately a
// little longer: it gives TTA time to hit that cap and return what it managed
// to fetch, which is a more informative failure than a timeout here.
const bulkTimeout = 20 * time.Second

// TestSmallMTUUnderlayThroughput reproduces the data-plane half of
// tailscale/tailscale#20668: on a path whose real MTU is smaller than the MTU
// tailscaled assumes, small packets flow but bulk transfers collapse, and
// nothing in tailscaled notices.
//
// The nodes get a direct UDP path whose MTU is [underlayMTU] (1280). A
// full-size TUN packet is 1280 bytes, and WireGuard/UDP/IPv4 framing adds 60,
// so a full-size packet needs 1340 bytes of underlay and does not fit. But
// tailscaled credits an unprobed path with tstun.SafeWireMTU() (1360, see
// pingSizeToPktLen in wgengine/magicsock/endpoint.go), so it believes the path
// is big enough and keeps emitting packets that are silently dropped. Peer MTU
// discovery is off by default (magicsock.Conn.ShouldPMTUD), and even when on,
// the probed MTU never reaches the data path (see the TODO in
// net/tstun/mtu.go's DefaultTUNMTU).
//
// This is the asymmetry the reporter saw: `tailscale ping` and interactive use
// look healthy while downloads are unusable. So the test asserts both halves —
// that a disco ping succeeds over a direct path, and that a bulk transfer over
// that same path completes.
//
// The bulk transfer is what currently fails. vnet drops the oversized packets
// without an ICMP "fragmentation needed" (see [vnet.Network.SetMTU]), which
// models the reporter's case: their packets were fragmented rather than
// dropped, but either way nothing tells the sender to reduce its packet size.
//
// Note that only the node-to-node underlay is constrained. Each node's path to
// the control plane and DERP is served by vnet's netstack and is unaffected, so
// a failure here is the peer-to-peer data plane and not a broken control plane.
func TestSmallMTUUnderlayThroughput(t *testing.T) {
	if !*runUnfixedTests {
		t.Skip("skipping test for unfixed bug tailscale/tailscale#20668; set --run-unfixed-tests to run")
	}
	env := vmtest.New(t)

	// One network per node, each with an MTU-constrained WAN link, so the
	// constraint applies in both directions regardless of which side sends.
	// EasyNAT so the two can still establish a direct path: the point is a
	// direct path that is too narrow, not the absence of one.
	addNode := func(name string, num int) *vmtest.Node {
		nw := env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", num, num, num), // public IP
			fmt.Sprintf("192.168.%d.1/24", num),
			vnet.EasyNAT)
		nw.SetMTU(underlayMTU)
		return env.AddNode(name, nw,
			vmtest.OS(vmtest.Gokrazy),
			vmtest.WebServer(8080))
	}
	a := addNode("a", 1)
	b := addNode("b", 2)

	env.Start()

	// A direct path is a precondition, not the thing under test: over DERP
	// (TCP to a netstack-terminated VIP) the underlay MTU wouldn't apply and
	// the test would pass for the wrong reason.
	if err := env.PingExpect(a, b, vmtest.PingRouteDirect, 60*time.Second); err != nil {
		t.Fatalf("precondition: want a direct path between the nodes: %v", err)
	}

	// Small packets fit within the underlay MTU, so this must keep working
	// even while bulk transfers do not. This is the "pings stay fast while
	// downloads are unusable" symptom.
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		t.Errorf("small-packet TSMP ping failed; expected small packets to fit under the %d-byte MTU: %v",
			underlayMTU, err)
	}

	// Enough data to require many full-size packets (819 of them): a transfer
	// this size cannot complete if every full-size packet is dropped, but
	// needs only ~100 KiB/s to finish inside the 10s budget TTA allows, which
	// vnet clears comfortably.
	const wantBytes = 1 << 20
	n, d, err := env.HTTPGetN(a, b, wantBytes, bulkTimeout)
	if err != nil {
		t.Errorf("bulk transfer over a %d-byte-MTU path failed after %d of %d bytes: %v\n"+
			"This is tailscale/tailscale#20668: tailscaled credits an unprobed path with "+
			"tstun.SafeWireMTU() (%d bytes) and never learns the real one, so every "+
			"full-size packet is dropped.",
			underlayMTU, n, wantBytes, err, tstun.SafeWireMTU())
		return
	}
	t.Logf("transferred %d bytes in %v (%.1f Mbit/s)",
		n, d.Round(time.Millisecond), float64(n)*8/d.Seconds()/1e6)
}

// TestLargeMTUUnderlayThroughput is the control for
// [TestSmallMTUUnderlayThroughput]: the same topology and the same transfer,
// but with an underlay MTU large enough for a full-size packet plus framing.
// It shares everything with that test except the one variable under study, so
// if this fails too the fault is in the harness rather than in the MTU
// handling. Unlike that test it is expected to pass, so it runs in CI.
func TestLargeMTUUnderlayThroughput(t *testing.T) {
	env := vmtest.New(t)

	addNode := func(name string, num int) *vmtest.Node {
		nw := env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", num, num, num),
			fmt.Sprintf("192.168.%d.1/24", num),
			vnet.EasyNAT)
		// 1500, the common Ethernet MTU: comfortably above the 1340 bytes a
		// full-size TUN packet needs on the wire.
		nw.SetMTU(1500)
		return env.AddNode(name, nw,
			vmtest.OS(vmtest.Gokrazy),
			vmtest.WebServer(8080))
	}
	a := addNode("a", 1)
	b := addNode("b", 2)

	env.Start()

	if err := env.PingExpect(a, b, vmtest.PingRouteDirect, 60*time.Second); err != nil {
		t.Fatalf("precondition: want a direct path between the nodes: %v", err)
	}

	const wantBytes = 1 << 20
	n, d, err := env.HTTPGetN(a, b, wantBytes, bulkTimeout)
	if err != nil {
		t.Fatalf("bulk transfer over a 1500-byte-MTU path failed; "+
			"the harness itself may be broken: %v", err)
	}
	t.Logf("transferred %d bytes in %v (%.1f Mbit/s)",
		n, d.Round(time.Millisecond), float64(n)*8/d.Seconds()/1e6)
}
