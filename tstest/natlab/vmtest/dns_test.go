// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

// TestMagicDNS verifies that control-plane DNS config makes it all the
// way into an Ubuntu guest's OS resolver, and that MagicDNS answers
// track netmap changes. Booting a VM is expensive, so this one test
// covers several scenarios in sequence:
//
//   - DNSConfig.ExtraRecords resolve via libc (getent), and search
//     domains let bare names resolve, which requires tailscaled to
//     have plumbed MagicDNS routes and search domains into
//     systemd-resolved.
//   - A peer added by control resolves by FQDN and by short name,
//     and its IP reverse-resolves (PTR) to its name.
//   - A peer renamed by control resolves under its new name only:
//     the old name must stop resolving, and PTR must track the new
//     name. When a node is renamed in the admin console, the control
//     plane sends peers a single MapResponse delta: a PeersChanged
//     entry containing the full updated Node with the new Name, and
//     notably no new DNSConfig (MagicDNS records are computed
//     client-side from peer names). This test injects deltas of
//     exactly that shape. It reproduces tailscale/corp#45631, where
//     a renamed node's old name kept resolving.
//   - A peer removed by control stops resolving.
func TestMagicDNS(t *testing.T) {
	env := vmtest.New(t, vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"tailnet.test", "record"},
		Routes: map[string][]*dnstype.Resolver{
			"tailnet.test": nil,
			"record":       nil,
		},
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "extratest.record", Type: "A", Value: "1.2.3.4"},
		},
	}))
	node := env.AddNode("node",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Ubuntu2404))
	env.Start()

	dt := &dnsTester{t: t, env: env, node: node}

	// ExtraRecords, by full name and via the "record" search domain.
	dt.wantResolves("extratest.record", "1.2.3.4")
	dt.wantResolves("extratest", "1.2.3.4")

	nodeKey := env.Status(node).Self.PublicKey
	cs := env.ControlServer()

	// Add a peer the way control does, as a PeersChanged delta
	// carrying the full node.
	peerAddr := netip.MustParsePrefix("100.64.7.7/32")
	peer := &tailcfg.Node{
		ID:                7777,
		StableID:          "peer1renamed",
		Name:              "renamee.tailnet.test.",
		User:              7777,
		Key:               key.NewNode().Public(),
		Machine:           key.NewMachine().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{peerAddr},
		AllowedIPs:        []netip.Prefix{peerAddr},
		Hostinfo:          (&tailcfg.Hostinfo{OS: "linux", Hostname: "renamee"}).View(),
		Cap:               tailcfg.CurrentCapabilityVersion,
		MachineAuthorized: true,
	}
	if !cs.AddRawMapResponse(nodeKey, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{peer},
	}) {
		t.Fatal("AddRawMapResponse(add peer): node not connected")
	}
	dt.wantResolves("renamee.tailnet.test", "100.64.7.7")
	dt.wantResolves("renamee", "100.64.7.7") // via search domain
	dt.wantResolves("100.64.7.7", "renamee.tailnet.test")

	// Rename the peer, sending the same delta shape production
	// control sends: the full node again with only the Name changed.
	renamed := peer.Clone()
	renamed.Name = "renamed.tailnet.test."
	if !cs.AddRawMapResponse(nodeKey, &tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{renamed},
	}) {
		t.Fatal("AddRawMapResponse(rename peer): node not connected")
	}
	dt.wantResolves("renamed.tailnet.test", "100.64.7.7")
	dt.wantResolves("renamed", "100.64.7.7")
	dt.wantResolves("100.64.7.7", "renamed.tailnet.test")
	dt.wantNXDOMAIN("renamee.tailnet.test")
	dt.wantNXDOMAIN("renamee")

	// Remove the peer; its name must stop resolving.
	if !cs.AddRawMapResponse(nodeKey, &tailcfg.MapResponse{
		PeersRemoved: []tailcfg.NodeID{peer.ID},
	}) {
		t.Fatal("AddRawMapResponse(remove peer): node not connected")
	}
	dt.wantNXDOMAIN("renamed.tailnet.test")
}

// dnsTester asserts DNS state in a guest via libc lookups (getent),
// retrying for a bit because tailscaled applies netmap and DNS config
// changes asynchronously.
type dnsTester struct {
	t    *testing.T
	env  *vmtest.Env
	node *vmtest.Node
}

// wantResolves waits until name resolves and its answer contains want.
// With an IP address as name, getent does a reverse (PTR) lookup and
// want is the expected hostname. It flushes systemd-resolved's cache
// before each attempt so it tests tailscaled's resolver rather than a
// previously cached answer.
func (dt *dnsTester) wantResolves(name, want string) {
	dt.t.Helper()
	if err := tstest.WaitFor(30*time.Second, func() error {
		dt.env.SSHExec(dt.node, "resolvectl flush-caches")
		out, err := dt.env.SSHExec(dt.node, "getent hosts "+name)
		if err != nil {
			return fmt.Errorf("getent hosts %s: %v (%s)", name, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, want) {
			return fmt.Errorf("getent hosts %s = %q, want it to contain %q", name, strings.TrimSpace(out), want)
		}
		return nil
	}); err != nil {
		out, _ := dt.env.SSHExec(dt.node, "resolvectl status; cat /etc/resolv.conf")
		dt.t.Fatalf("%v\nresolver state:\n%s", err, out)
	}
}

// wantNXDOMAIN waits until name no longer resolves. It flushes
// systemd-resolved's cache before each attempt so it tests
// tailscaled's resolver rather than a previously cached answer.
func (dt *dnsTester) wantNXDOMAIN(name string) {
	dt.t.Helper()
	if err := tstest.WaitFor(30*time.Second, func() error {
		dt.env.SSHExec(dt.node, "resolvectl flush-caches")
		out, err := dt.env.SSHExec(dt.node, "getent hosts "+name)
		if err == nil {
			return fmt.Errorf("%s still resolves: %q", name, strings.TrimSpace(out))
		}
		return nil
	}); err != nil {
		dt.t.Fatal(err)
	}
}

func TestSplitDNS(t *testing.T) {
	testSplitDNS(t, vmtest.DNSDefault, "systemd-resolved")
}

func TestSplitDNSDirect(t *testing.T) {
	testSplitDNS(t, vmtest.DNSDirect, "direct")
}

// testSplitDNS checks that a Tailscale node sends DNS queries to the right
// place. "Split DNS" means the tailnet can say "queries for domain X go to
// resolver Y", instead of every query going to the machine's default DNS
// server. Control sends that policy as DNSConfig.Routes: a map of domain
// suffix to the resolver(s) for it.
//
// A route's resolver list can also be empty, which means something different:
// don't forward those queries anywhere, let tailscaled's own resolver
// (100.100.100.100, "quad-100") answer them from what it knows -- the tailnet's
// MagicDNS names and any extra records control sent.
//
// So there are four ways a lookup can be resolved, and this test covers all
// four. Each is one row of the checks table below:
//
//  1. forwarded: a domain routed to a specific resolver goes to that resolver.
//  2. local: a domain routed with an empty resolver list is answered by
//     quad-100 from an extra record control sent.
//  3. magicdns: a peer's tailnet name is answered by quad-100 from the netmap.
//  4. default: a domain with no route at all still goes to the machine's normal
//     DNS server, i.e. Tailscale doesn't hijack unrelated lookups.
//
// Here quad-100 is the one that forwards case 1, on both DNS backends: this
// config mixes routes with different resolvers (one forwarded, two local), and
// tailscaled only lets the OS resolver do the forwarding when every route shares
// a single resolver set. [TestSplitDNSOSForwarded] covers that other
// arrangement. What the two backends differ in here is how a query reaches
// quad-100: systemd-resolved is told to match just the routed suffixes onto the
// Tailscale link, so case 4 never goes near quad-100, whereas the "direct"
// backend can't express that, so the OS points everything at quad-100 and
// tailscaled forwards case 4 onward itself.
//
// dnsMode picks the backend; wantBackend is asserted so a pass can't come from
// the wrong one.
func testSplitDNS(t *testing.T, dnsMode vmtest.DNSMode, wantBackend string) {
	t.Helper()

	// ---- Setup: the DNS policy we'll hand to the node, and what each case
	// ---- should resolve to.

	// Case 1 (forwarded). vnet runs a second DNS server that is the *only*
	// thing serving fwdName. If the node resolves fwdName correctly, the query
	// must have been forwarded to that server -- nothing else could have
	// answered it. That's what makes this a real test of split DNS.
	fwdDomain := vnet.SplitDNSDomain()
	fwdName, fwdIP := vnet.SplitDNSName()
	fwdResolver := vnet.FakeSplitDNSIPv4()

	// Case 2 (local). A route with no resolvers, plus an extra record for a name
	// in it. localIP is arbitrary -- the checks only resolve names, never connect
	// -- but it's in the tailnet range and outside the 100.64.x.y block
	// testcontrol assigns nodes, so an answer can only have come from the extra
	// record.
	const localDomain = "local.example"
	const localName = "host." + localDomain
	const localIP = "100.99.99.99"

	// Case 3 (magicdns). The peer's node name becomes its guest hostname, and
	// control appends the tailnet's MagicDNS domain, so its name is predictable.
	const magicDNSDomain = "tailnet.test"
	const peerNodeName = "peer"
	const wantPeerName = peerNodeName + "." + magicDNSDomain

	// Case 4 (default) uses a name that only vnet's *default* DNS server serves;
	// see the checks table.

	env := vmtest.New(t,
		vmtest.SameTailnetUser(), // so the peer is visible and its MagicDNS name resolves
		vmtest.ControlDNS(magicDNSDomain, &tailcfg.DNSConfig{
			Proxied: true, // turn on MagicDNS (needed for case 3)
			// Search domains, so the bare name "host" also resolves as
			// host.local.example.
			Domains: []string{localDomain},
			Routes: map[string][]*dnstype.Resolver{
				fwdDomain:   {{Addr: fwdResolver.String()}}, // case 1: forward here
				localDomain: nil,                            // case 2: answer locally
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: localName, Type: "A", Value: localIP}, // case 2's answer
			},
		}))

	// Two nodes: client is the one we run lookups on; peer exists only so there's
	// a tailnet name to look up (case 3). Nothing runs on peer.
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	client := env.AddNode("client", lan,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.WithDNSMode(dnsMode))
	peer := env.AddNode(peerNodeName, lan,
		vmtest.OS(vmtest.Ubuntu2404))

	env.Start()

	// Last bit of setup: read the peer's tailnet name and IP, which are case 3's
	// lookup and expected answer. We check the name matches what control should
	// have assigned rather than just using whatever it reports, so that if
	// MagicDNS naming changes, this fails loudly instead of quietly resolving
	// some other name and still passing.
	peerSt := env.Status(peer)
	peerName := strings.TrimSuffix(peerSt.Self.DNSName, ".")
	if peerName != wantPeerName {
		t.Fatalf("peer DNSName = %q, want %q", peerName, wantPeerName)
	}
	var peerIP string // IPv4, since the lookups below ask for A records only
	for _, a := range peerSt.Self.TailscaleIPs {
		if a.Is4() {
			peerIP = a.String()
			break
		}
	}
	if peerIP == "" {
		t.Fatalf("peer has no IPv4 TailscaleIP in status (got %v)", peerSt.Self.TailscaleIPs)
	}

	// ---- Checks start here.

	// First, confirm the client picked the DNS backend this run is meant to
	// exercise, so the lookups below can't pass via the other backend.
	env.AssertDNSBackend(client, wantBackend)

	// Also confirm the machine's resolver points at quad-100 and was *not* handed
	// the split resolver: this config landed in the "quad-100 forwards"
	// arrangement described above, not the OS-forwarded one.
	assertResolverState(t, env, client,
		[]string{"100.100.100.100"},
		[]string{fwdResolver.String()})

	// Then resolve each name on the client and confirm the answer, which tells us
	// the query went where it should have.
	//
	// We use "getent ahostsv4" (A records only) rather than "getent hosts":
	// dualstack-web.example.com has both A and AAAA, and "hosts" can return
	// either family.
	checks := []struct {
		name string // what to look up on the client
		want string // the answer proving it was resolved by the right thing
		what string // which of the four cases this is, for failure messages
	}{
		// Only vnet's second DNS server serves this name, so getting the right
		// answer proves the query was forwarded there.
		{fwdName, fwdIP.String(), "1. forwarded: routed domain went to its designated resolver"},
		// Served by quad-100 from control's extra record, not forwarded anywhere.
		{localName, localIP, "2. local: empty-resolver route answered by quad-100"},
		// Same answer, but looked up as a bare name to check the search domain.
		{"host", localIP, "2. local: bare name completed by the " + localDomain + " search domain"},
		// quad-100 answers tailnet names from the netmap.
		{peerName, peerIP, "3. magicdns: peer's tailnet name resolved to its tailnet IP"},
		// No route covers this, so it must still reach the normal DNS server
		// (here vnet's default one, standing in for the internet).
		{"dualstack-web.example.com", "5.0.0.100", "4. default: unrouted name still resolved normally"},
	}

	for _, c := range checks {
		// Retry: tailscaled applies DNS config to the OS resolver
		// asynchronously after coming up.
		if err := tstest.WaitFor(30*time.Second, func() error {
			out, err := env.SSHExec(client, "getent ahostsv4 "+c.name)
			if err != nil {
				return fmt.Errorf("getent ahostsv4 %s (%s): %v (%s)", c.name, c.what, err, strings.TrimSpace(out))
			}
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("getent ahostsv4 %s (%s) = %q, want it to contain %s", c.name, c.what, strings.TrimSpace(out), c.want)
			}
			return nil
		}); err != nil {
			out, _ := env.SSHExec(client, "resolvectl status; cat /etc/resolv.conf")
			t.Fatalf("%v\nclient resolver state:\n%s", err, out)
		}
	}
}

// TestSplitDNSOSForwarded covers the other way Tailscale can implement a
// split-DNS route: letting the OS resolver forward the routed domain straight to
// its designated resolver, with quad-100 out of the query path entirely.
//
// tailscaled only does this when the OS resolver supports split DNS *and* every
// route shares one resolver set, since a single set is all it can hand the OS
// (see compileConfig in net/dns/manager.go). So unlike [testSplitDNS], the
// config here has exactly one route and no MagicDNS: nothing needs answering
// locally, so there's nothing for quad-100 to do. systemd-resolved then gets the
// split resolver as its nameserver, with the routed domain as a match domain.
//
// The lookup is the same shape as testSplitDNS case 1, but it proves more here:
// with quad-100 not in the path, an answer means systemd-resolved sent the query
// to the split resolver itself.
//
// There is no "direct" variant of this test. The direct backend rewrites
// resolv.conf, which can't express "this domain goes elsewhere", so it reports
// SupportsSplitDNS() == false and tailscaled always falls back to forwarding via
// quad-100 -- which is what [TestSplitDNSDirect] covers.
func TestSplitDNSOSForwarded(t *testing.T) {
	// ---- Setup.

	// The routed domain and the resolver that serves it. Only vnet's second DNS
	// server answers this name, so resolving it proves the query got there.
	fwdDomain := vnet.SplitDNSDomain()
	fwdName, fwdIP := vnet.SplitDNSName()
	fwdResolver := vnet.FakeSplitDNSIPv4()

	// systemd-resolved sends queries for a match domain out the link it
	// programmed them on -- the Tailscale interface -- so the split resolver has
	// to be reachable over the tailnet, as it would be in a real deployment
	// (a resolver inside a subnet-routed network). Advertise a route covering
	// fwdResolver from a second node and accept it on the client.
	fwdResolverRoute := netip.PrefixFrom(fwdResolver, 32).String()

	env := vmtest.New(t,
		// No Proxied/MagicDNS and no empty-resolver routes: a single route with a
		// single resolver is what makes tailscaled hand the split to the OS.
		vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
			Routes: map[string][]*dnstype.Resolver{
				fwdDomain: {{Addr: fwdResolver.String()}},
			},
		}))

	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	client := env.AddNode("client", lan,
		vmtest.OS(vmtest.Ubuntu2404))
	// This node exists only to make fwdResolver routable over the tailnet; no
	// DNS server runs on it. vnet answers the queries once they're on the wire.
	resolverRouter := env.AddNode("resolver-router", lan,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.AdvertiseRoutes(fwdResolverRoute))

	env.Start()

	// ApproveRoutes also turns on accept-routes on the other nodes, so the
	// client installs the route to fwdResolver.
	env.ApproveRoutes(resolverRouter, fwdResolverRoute)

	// ---- Checks start here.

	env.AssertDNSBackend(client, "systemd-resolved")

	// The resolver state is the direct evidence for this branch: systemd-resolved
	// was given the split resolver as its server for the routed domain, and
	// quad-100 is nowhere in the query path. Asserting this is what separates
	// this test from [testSplitDNS] -- the lookup below would also pass if
	// quad-100 were doing the forwarding.
	assertResolverState(t, env, client,
		[]string{fwdResolver.String(), "~" + fwdDomain},
		[]string{"100.100.100.100"})

	// And it works end to end: the OS resolves the name, which only the split
	// resolver serves.
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(client, "getent ahostsv4 "+fwdName)
		if err != nil {
			return fmt.Errorf("getent ahostsv4 %s: %v (%s)", fwdName, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, fwdIP.String()) {
			return fmt.Errorf("getent ahostsv4 %s = %q, want it to contain %s", fwdName, strings.TrimSpace(out), fwdIP)
		}
		return nil
	}); err != nil {
		out, _ := env.SSHExec(client, "resolvectl status; cat /etc/resolv.conf; ip route")
		t.Fatalf("%v\nclient resolver state:\n%s", err, out)
	}
}

// assertResolverState fails the test unless the node's OS resolver state has
// every string in want and none in notWant, retrying while tailscaled applies
// its config asynchronously.
//
// notWant is how each caller pins down which of tailscaled's two split-DNS
// arrangements ran: they answer queries identically, so the resolver that is
// *absent* identifies the branch as much as the one that's there.
//
// It reads both resolvectl and resolv.conf because the backends record state in
// different places: systemd-resolved keeps servers and domains per-link, with
// resolv.conf just the 127.0.0.53 stub, while the direct backend writes
// resolv.conf itself and leaves resolved masked and not running.
//
// Each want and notWant is matched as a whitespace-separated token, so pass
// exactly what appears in the output: a bare resolver address, or a routing-only
// ("match") domain with resolvectl's "~" prefix and no trailing dot. The
// resolvectl queries are scoped to tailscale0, so a match can't come from
// another link; if the interface is ever named otherwise, resolvectl errors and
// the assertion fails rather than silently matching elsewhere.
func assertResolverState(t *testing.T, env *vmtest.Env, n *vmtest.Node, want, notWant []string) {
	t.Helper()
	// Keep resolvectl's stderr: it's how resolved being absent (expected under
	// the direct backend) or broken (not) shows up in the failure dump.
	const cmd = "resolvectl dns tailscale0 2>&1; resolvectl domain tailscale0 2>&1; cat /etc/resolv.conf 2>&1"
	var last string
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(n, cmd)
		last = out
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		got := strings.Fields(out)
		for _, w := range want {
			if !slices.Contains(got, w) {
				return fmt.Errorf("resolver state is missing %q", w)
			}
		}
		for _, w := range notWant {
			if slices.Contains(got, w) {
				return fmt.Errorf("resolver state unexpectedly has %q", w)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%v\nwant all of %q and none of %q in resolver state:\n%s", err, want, notWant, last)
	}
}
