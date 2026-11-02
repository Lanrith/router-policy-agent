package firewall

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// Raw directory intent must survive the original compiler and renderer before
// callback projection. Handwritten logical rows alone are not this evidence.
func TestNAT64CallbackTargetGrantsRequireCompiledDirectoryPermission(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                               string
		active, access, ready, bound, deny bool
		protocol                           string
		port                               uint16
		want                               bool
	}{
		{"exact listener", true, true, true, true, false, "tcp", 6062, true},
		{"inactive recipient", false, true, true, true, false, "tcp", 6062, false},
		{"placement only", true, false, true, true, false, "tcp", 6062, false},
		{"unready alias", true, true, false, true, false, "tcp", 6062, false},
		{"missing recipient ownership", true, true, true, false, false, "tcp", 6062, false},
		{"earlier owner deny", true, true, true, true, true, "tcp", 6062, false},
		{"wrong protocol", true, true, true, true, false, "udp", 6062, false},
		{"wrong listener", true, true, true, true, false, "tcp", 6063, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := nat64TransportFixture(t)
			baseline.NetworkModel.ManagedNetworks = []policy.Role{baseline.Zones[1].Role}
			baseline.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b:3::10"), Alias: netip.MustParseAddr("10.251.0.20"), Ready: test.ready}}
			baseline.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6062},
				From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.0/24")}},
				To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:3::10/128")}}}}
			if test.deny {
				deny := baseline.NetworkModel.Rules[0]
				deny.Action, deny.Authorization = "deny", "owner"
				baseline.NetworkModel.Rules = append([]policy.NetworkRule{deny}, baseline.NetworkModel.Rules...)
			}
			transport, err := newNativeNAT64Transport(t.Context(), baseline, "nat64-internal")
			if err != nil {
				t.Fatal(err)
			}
			callback, err := newNativeNAT64CallbackTransport(t.Context(), transport)
			if err != nil {
				t.Fatal(err)
			}
			model, err := newNativeNAT64CallbackModel(t.Context(), baseline, callback)
			if err != nil {
				t.Fatal(err)
			}
			renderer, err := newRenderer(baseline)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, input := renderFixture(t)
			now := time.Now().UTC()
			input.Now, input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now, now
			input.Directory.Groups = input.Directory.Groups[:1]
			device := &input.Directory.Devices[0]
			device.MAC, device.Active, device.GroupIDs = "02:00:00:00:00:13", test.active, []string{input.Directory.Groups[0].ID}
			if test.access {
				// IPv4 peers retain their native family in the raw policy.
				group := rendererAccessGroup(t, "callback-recipient", false, policy.Rule{ID: "listener", Direction: policy.ToDevice,
					Peer: policy.Peer{Addresses: []string{"10.240.0.10/32"}}, Protocol: test.protocol, DestinationPorts: []uint16{test.port}, Reason: "Synthetic callback recipient"})
				input.Directory.Groups = append(input.Directory.Groups, group)
				device.GroupIDs = append(device.GroupIDs, group.ID)
			}
			input.Bindings.Records = []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
				AssociatedAt: now, AssociationID: "callback-caller", Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.0.10"), Source: "kea_dhcp4", OwnershipID: "callback-caller4", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}
			if test.bound {
				input.Bindings.Records = append(input.Bindings.Records, binding.Record{MAC: device.MAC, NAS: "synthetic-nas", Interface: "lan13", VLAN: 13,
					AssociatedAt: now, AssociationID: "callback-recipient", Addresses: []binding.Address{{IP: netip.MustParseAddr("fdca:1a2b:3::10"), Source: "qualified_ipv6", OwnershipID: "callback-recipient6", ObservedAt: now, ValidUntil: now.Add(70 * time.Second)}}})
			}
			authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
			if err != nil {
				t.Fatal(err)
			}
			logical, err := renderer.prepare(t.Context(), replacement{authorization: authorization, now: time.Now().UTC(), cohort: []string{device.MAC}})
			if err != nil {
				t.Fatal(err)
			}
			history := state.Classification{MACs: []string{device.MAC}, IPv4: []string{}, IPv6: []string{}}
			addresses, err := renderer.compiler.ClassifyBindings(t.Context(), input.Bindings, history.MACs, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range addresses {
				if address.Is4() {
					history.IPv4 = append(history.IPv4, address.String())
				} else {
					history.IPv6 = append(history.IPv6, address.String())
				}
			}
			mapped, err := prepareMappedGuards(t.Context(), logical, &history, nil)
			if err != nil {
				t.Fatal(err)
			}
			var changes guardChanges
			if err := json.Unmarshal(mapped.batch.data, &changes); err != nil {
				t.Fatal(err)
			}
			ownership, err := renderer.compiler.CompileOwnership(t.Context(), input.Bindings, now, policy.CaptureAge())
			if err != nil {
				t.Fatal(err)
			}
			ownership, err = ownership.InEpoch(t.Context(), 7)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := renderer.prepareNativeOwnership(t.Context(), ownership, now)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := nativeSourceReceipt(t.Context(), prepared)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, transport.mappings)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := ledger.Snapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			origin := &nativeNAT64GrantOrigin{transport: transport, ledger: ledger, readiness: &testNAT64Readiness{transport: transport, entries: entries, ready: true}}
			commands, err := model.projectTargetGrants(t.Context(), changes, receipt, now, time.Now(), origin)
			if err != nil {
				t.Fatal(err)
			}
			rows := 0
			for _, command := range commands {
				if command.Add != nil {
					rows += len(command.Add.Element.Values)
				}
			}
			if (rows == 4) != test.want || !test.want && rows != 0 {
				t.Fatal("callback projection changed compiled directory permission", rows, test.want)
			}
		})
	}
}
