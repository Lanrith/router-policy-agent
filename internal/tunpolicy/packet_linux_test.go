//go:build integration && linux

package tunpolicy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// This test-only controller runs inside the platform's isolated packet fixture.
// Its inputs are synthetic observations, not a production IPC or executable.
// Actual policy evidence, publisher transactions, executable checks, nftables
// and connection deletion are used while Python checks application delivery.
func TestTUNPacketPublisher(t *testing.T) {
	root := os.Getenv("LANRITH_TUN_PACKET_FIXTURE")
	if root == "" {
		t.Skip("requires the isolated platform TUN packet fixture")
	}
	data, err := os.ReadFile(filepath.Join(root, "baseline.json")) //nolint:gosec // Test-only compiled fixture chosen by the isolated test runner, never a runtime input.
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := policy.DecodeBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := OpenExecutor(t.Context(), "/usr/sbin/nft", "/usr/sbin/conntrack")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := executor.Close(); err != nil {
			t.Error(err)
		}
	})
	// Only the test derives its pin from the freshly installed fixture. The
	// production helper requires the independently built immutable profile.
	listing, _, err := run(t.Context(), executor.nft, "", "-j", "-n", "list", "ruleset")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ProgramDigest([]byte(listing))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(baseline, Options{Clock: time.Now, Commit: executor.Commit, Invalidate: executor.Invalidate})
	if err != nil {
		t.Fatal(err)
	}
	var input policy.Input
	var previous policy.Authorization
	history := state.EmptyClassification()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		var request struct {
			Command  string `json:"command"`
			Protocol string `json:"protocol"`
			LeaseMS  int    `json:"lease_ms"`
			Bindings []struct {
				MAC       string   `json:"mac"`
				Interface string   `json:"interface"`
				Addresses []string `json:"addresses"`
			} `json:"bindings"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			t.Fatal(err)
		}
		if err := executor.Inspect(t.Context(), digest); err != nil {
			t.Fatal(err)
		}
		switch request.Command {
		case "initialize":
			now := time.Now().UTC()
			input = policy.Input{Now: now, Bindings: binding.Snapshot{SchemaVersion: 1,
				Generation: "packet-bindings", ObservedAt: now, Complete: true}}
			for i, entry := range request.Bindings {
				record := binding.Record{MAC: entry.MAC, NAS: "synthetic-switch", Interface: entry.Interface,
					AssociatedAt: now, AssociationID: fmt.Sprintf("association-%d", i)}
				history.MACs = append(history.MACs, entry.MAC)
				for j, text := range entry.Addresses {
					address, parseErr := netip.ParseAddr(text)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					source := "qualified_ipv6"
					if address.Is4() {
						source = "kea_dhcp4"
						history.IPv4 = append(history.IPv4, text)
					} else {
						history.IPv6 = append(history.IPv6, text)
					}
					record.Addresses = append(record.Addresses, binding.Address{IP: address, Source: source,
						OwnershipID: fmt.Sprintf("lease-%d-%d", i, j), ObservedAt: now, ValidUntil: now.Add(time.Minute)})
				}
				input.Bindings.Records = append(input.Bindings.Records, record)
			}
			slices.Sort(history.MACs)
			slices.Sort(history.IPv4)
			slices.Sort(history.IPv6)
			if err := b.Close(t.Context(), history); err != nil {
				t.Fatal(err)
			}
			configuration, compileErr := compiler.CompileOwnerConfiguration(t.Context(), 1)
			if compileErr != nil {
				t.Fatal(compileErr)
			}
			if err := b.RefreshConfiguration(t.Context(), configuration); err != nil {
				t.Fatal(err)
			}
			publish(t, b, input, compiler)
		case "grant":
			input.Now = time.Now().UTC()
			observed := input.Now
			if request.LeaseMS != 0 {
				observed = observed.Add(-time.Duration(baseline.LeaseSeconds)*time.Second + time.Duration(request.LeaseMS)*time.Millisecond)
			}
			input.Directory = policy.DirectorySnapshot{ObservedAt: observed, Complete: true}
			for i, record := range input.Bindings.Records {
				role, peer := "six", "10.240.40.2/32"
				if record.Interface == "c4" {
					role, peer = "four", "fd42:1234:5678:20::10/128"
				}
				placement := fmt.Sprintf(`{"schema_version":1,"kind":"placement","vlan_role":%q}`, role)
				access := fmt.Sprintf(`{"schema_version":1,"kind":"access","vlan_role":%q,"temporary":false,"rules":[{"id":"callback","direction":"to_device","peer":{"addresses":[%q]},"protocol":%q,"destination_ports":[22222],"reason":"synthetic callback"}]}`, role, peer, request.Protocol)
				placementID, accessID := fmt.Sprintf("placement-%d", i), fmt.Sprintf("access-%d", i)
				input.Directory.Groups = append(input.Directory.Groups,
					policy.Group{ID: placementID, Name: placementID, Policy: &placement, IsNetwork: true},
					policy.Group{ID: accessID, Name: accessID, Policy: &access, IsNetwork: true})
				input.Directory.Devices = append(input.Directory.Devices, policy.Device{ID: fmt.Sprintf("device-%d", i), MAC: record.MAC,
					Active: true, GroupIDs: []string{placementID, accessID}})
			}
			previous = authorize(t, input, compiler)
			if err := b.Apply(t.Context(), previous, history); err != nil {
				t.Fatal(err)
			}
		case "revoke":
			if err := b.Seal(t.Context(), history); err != nil {
				t.Fatal(err)
			}
		case "rotate":
			input.Now = time.Now().UTC()
			for i := range input.Bindings.Records {
				input.Bindings.Records[i].AssociationID += "-next"
			}
			publish(t, b, input, compiler)
		case "replay":
			if err := b.Apply(t.Context(), previous, history); err == nil {
				t.Fatal("old authorization accepted after binding rotation or expiry")
			}
		case "close":
			if err := b.Close(t.Context(), history); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown packet fixture command")
		}
		if err := executor.Inspect(t.Context(), digest); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stdout, "ACK "+request.Command); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
