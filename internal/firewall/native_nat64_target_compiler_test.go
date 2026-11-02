package firewall

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// Exercise raw directory policy through the privileged compiler and renderer,
// rather than supplying logical grant rows directly to the NAT64 projection.
func TestNAT64TargetGrantsRequireCompiledDirectoryPermission(t *testing.T) {
	t.Parallel()
	for _, caller := range []struct {
		name                     string
		lifetime, targetLifetime time.Duration
		dynamic                  bool
	}{{"configured caller", 0, 90 * time.Second, false}, {"owned caller", 90 * time.Second, 90 * time.Second, false}, {"short caller ownership", 20 * time.Second, 90 * time.Second, false}, {"short target ownership", 90 * time.Second, 20 * time.Second, false}, {"dynamic configured caller", 0, 90 * time.Second, true}, {"dynamic owned caller", 90 * time.Second, 90 * time.Second, true}} {
		for _, test := range []struct {
			name                               string
			active, access, ready, bound, deny bool
			protocol                           string
			port                               uint16
			want                               bool
		}{
			{"exact listener", true, true, true, true, false, "tcp", 443, true},
			{"inactive account", false, true, true, true, false, "tcp", 443, false},
			{"placement only", true, false, true, true, false, "tcp", 443, false},
			{"unready source alias", true, true, false, true, false, "tcp", 443, false},
			{"missing ownership", true, true, true, false, false, "tcp", 443, false},
			{"earlier owner deny", true, true, true, true, true, "tcp", 443, false},
			{"different protocol", true, true, true, true, false, "udp", 443, false},
			{"different listener", true, true, true, true, false, "tcp", 444, false},
		} {
			t.Run(caller.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				b := nat64TransportFixture(t)
				b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[1].Role}
				if caller.lifetime > 0 {
					b.NetworkModel.ManagedNetworks = append(b.NetworkModel.ManagedNetworks, b.Zones[0].Role)
				}
				b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{443},
					From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
					To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.0/24")}}}}
				if test.deny {
					block := b.NetworkModel.Rules[0]
					block.Action, block.Authorization = "deny", "owner"
					b.NetworkModel.Rules = append([]policy.NetworkRule{block}, b.NetworkModel.Rules...)
				}
				b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: test.ready}}
				allocations := b.NAT64[0].SourceMappings
				if caller.dynamic {
					b.NAT64[0].SourceMappings = nil
				}
				renderer, err := newRenderer(b)
				if err != nil {
					t.Fatal(err)
				}
				transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
				if err != nil {
					t.Fatal(err)
				}
				_, _, _, input := renderFixture(t)
				anchor := policy.CaptureAge()
				now := time.Now().UTC()
				input.Now, input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now, now
				input.Directory.Groups = input.Directory.Groups[:1]
				device := &input.Directory.Devices[0]
				device.MAC, device.Active, device.GroupIDs = "02:00:00:00:00:13", test.active, []string{input.Directory.Groups[0].ID}
				if test.access {
					group := rendererAccessGroup(t, "target-listener", false, policy.Rule{ID: "listener", Direction: policy.ToDevice,
						Peer: policy.Peer{Addresses: []string{"fdca:1a2b::10/128"}}, Protocol: test.protocol, DestinationPorts: []uint16{test.port}, Reason: "Synthetic target listener"})
					input.Directory.Groups = append(input.Directory.Groups, group)
					device.GroupIDs = append(device.GroupIDs, group.ID)
				}
				input.Bindings.Records = []binding.Record{{MAC: device.MAC, NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: "compiled-target",
					Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "compiled-target-address", ObservedAt: now, ValidUntil: now.Add(caller.targetLifetime)}}}}
				if !test.bound {
					input.Bindings.Records = nil
				}
				if caller.lifetime > 0 {
					for _, row := range []struct {
						mac, address string
						lifetime     time.Duration
					}{{"02:00:00:00:00:09", "fdca:1a2b::9", 90 * time.Second}, {"02:00:00:00:00:10", "fdca:1a2b::10", caller.lifetime}} {
						input.Bindings.Records = append(input.Bindings.Records, binding.Record{MAC: row.mac, NAS: "synthetic-nas", Interface: "lan10", VLAN: 10, AssociatedAt: now, AssociationID: row.address, Addresses: []binding.Address{{IP: netip.MustParseAddr(row.address), Source: "qualified_ipv6", OwnershipID: row.address, ObservedAt: now, ValidUntil: now.Add(row.lifetime)}}})
					}
				}
				authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, anchor)
				if err != nil {
					t.Fatal(err)
				}
				logical, err := renderer.prepare(t.Context(), replacement{authorization: authorization, now: time.Now().UTC(), cohort: []string{device.MAC}})
				if err != nil {
					t.Fatal(err)
				}
				ownership, err := renderer.compiler.CompileOwnership(t.Context(), input.Bindings, now, policy.CaptureAge())
				if err != nil {
					t.Fatal(err)
				}
				ownership, err = ownership.InEpoch(t.Context(), 9)
				if err != nil {
					t.Fatal(err)
				}
				owned, err := renderer.prepareNativeOwnership(t.Context(), ownership, now)
				if err != nil {
					t.Fatal(err)
				}
				sources, err := nativeSourceReceipt(t.Context(), owned)
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
				var origins []*nativeNAT64GrantOrigin
				if caller.dynamic {
					ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, allocations)
					if err != nil {
						t.Fatal(err)
					}
					entries, err := ledger.Snapshot(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					proof := &testNAT64Readiness{transport: transport, entries: entries, ready: test.ready}
					origins = []*nativeNAT64GrantOrigin{{transport: transport, ledger: ledger, readiness: proof}}
				}
				prepared, err := prepareNativeNAT64Guards(t.Context(), mapped, sources, transport, logical.preparedAt, origins...)
				if caller.dynamic && !test.ready {
					if err == nil {
						t.Fatal("unready dynamic allocation projected a recipient grant")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
					t.Fatal("compiler-derived target grant rejected by privileged validation", err)
				}
				commands, err := decodeGuardChanges(prepared.batch.data)
				if err != nil {
					t.Fatal(err)
				}
				counts := map[objectReference]int{}
				for _, command := range commands.Commands {
					if command.Add != nil {
						element := command.Add.Element
						counts[objectReference{Family: element.Family, Table: element.Table, Name: element.Name}] += len(element.Values)
						if strings.HasPrefix(element.Name, "native_n64_from") && caller.lifetime > 0 {
							snapshot, snapshotErr := sources.evidence.Snapshot(t.Context())
							if snapshotErr != nil {
								t.Fatal(snapshotErr)
							}
							for _, row := range element.Values {
								fields, timeout := nativeSourceTimedTest(t, row)
								if len(fields) != 4 || string(fields[0]) != `"0:2402"` {
									t.Fatal("recipient grant borrowed another UID domain", string(row))
								}
								for index, address := range snapshot.Addresses {
									if address.Address.String() != "fdca:1a2b::10" && address.Address.String() != "10.240.3.10" {
										continue
									}
									remaining, deadlineErr := sources.remaining(t.Context(), index, prepared.sourceAnchor)
									if deadlineErr != nil || time.Duration(timeout)*time.Second+preparationBudget+commandBudget > remaining {
										t.Fatal("recipient grant escaped a caller or target ownership deadline", deadlineErr, timeout, remaining)
									}
								}
							}
						}
					}
				}
				for _, ref := range nativeNAT64GrantRefs() {
					want := 0
					if test.want && (ref.Name == "native_n64_to4_tcp" || ref.Name == "native_n64_to6_tcp") {
						want = 1
					}
					if test.want && caller.lifetime > 0 && (ref.Name == "native_n64_from4_tcp" || ref.Name == "native_n64_from6_tcp") {
						want = 1
					}
					if counts[ref] != want {
						t.Fatal("compiled directory intent lost its target scope or admitted another path", ref, counts[ref], want)
					}
				}
			})
		}
	}
}
