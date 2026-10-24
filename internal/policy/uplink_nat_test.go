package policy

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func uplinkNATBaseline(t *testing.T) Baseline {
	t.Helper()
	b := coreEgressBaseline(t)
	b.NetworkModel.UplinkNAT = []UplinkNAT{{Interface: "lan13", Sources: prefixes("10.240.3.0/24"), Addresses: []netip.Addr{netip.MustParseAddr("10.243.0.1")}}}
	return b
}

func TestUplinkNATContractOwnsGeometryAndGrantsNoPermission(t *testing.T) {
	t.Parallel()
	b := uplinkNATBaseline(t)
	compiler := testCompiler(t, b)
	hash := compiler.BaselineHash()
	b.NetworkModel.UplinkNAT[0].Sources[0] = netip.MustParsePrefix("0.0.0.0/0")
	b.NetworkModel.UplinkNAT[0].Addresses[0] = netip.MustParseAddr("10.243.0.99")
	if compiler.BaselineHash() != hash {
		t.Fatal("caller mutation changed owned NAT geometry")
	}
	_, input := namedFixture(t)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("NAT declaration changed permission", candidate.Denials, err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
}

func TestUplinkNATRejectsUnsafeSourcesAndDestinations(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"WAN attachment", "unknown attachment", "duplicate attachment", "missing source", "default source", "unattached source", "IPv6 source", "hostbits", "duplicate source", "nested sources", "IPv6 uplink address", "unprotected uplink address", "client uplink address", "duplicate uplink address", "different WAN inventories", "raw rules"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := uplinkNATBaseline(t)
			path := &b.NetworkModel.UplinkNAT[0]
			switch name {
			case "WAN attachment":
				path.Interface = "wan"
			case "unknown attachment":
				path.Interface = "absent0"
			case "duplicate attachment":
				b.NetworkModel.UplinkNAT = append(b.NetworkModel.UplinkNAT, *path)
			case "missing source":
				path.Sources = nil
			case "default source":
				path.Sources = prefixes("0.0.0.0/0")
			case "unattached source":
				path.Sources = prefixes("10.240.2.0/24")
			case "IPv6 source":
				path.Sources = prefixes("fdca:1a2b:3::/64")
			case "hostbits":
				path.Sources = prefixes("10.240.3.1/24")
			case "duplicate source":
				path.Sources = append(path.Sources, path.Sources[0])
			case "nested sources":
				path.Sources = append(path.Sources, netip.MustParsePrefix("10.240.3.0/25"))
			case "IPv6 uplink address":
				path.Addresses = []netip.Addr{netip.MustParseAddr("fdca:1a2b:ee00::1")}
			case "unprotected uplink address":
				path.Addresses = []netip.Addr{netip.MustParseAddr("10.243.0.99")}
			case "client uplink address":
				path.Addresses = []netip.Addr{netip.MustParseAddr("10.240.2.10")}
			case "duplicate uplink address":
				path.Addresses = append(path.Addresses, path.Addresses[0])
			case "different WAN inventories":
				b.NetworkModel.UplinkNAT = append(b.NetworkModel.UplinkNAT, UplinkNAT{Interface: "lan12", Sources: prefixes("10.240.2.0/24"), Addresses: []netip.Addr{}})
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if name == "raw rules" {
				var root map[string]any
				if err := json.Unmarshal(raw, &root); err != nil {
					t.Fatal(err)
				}
				model, ok := root["network_model"].(map[string]any)
				if !ok {
					t.Fatal("missing model")
				}
				paths, ok := model["uplink_nat"].([]any)
				if !ok {
					t.Fatal("missing NAT paths")
				}
				entry, ok := paths[0].(map[string]any)
				if !ok {
					t.Fatal("missing NAT path")
				}
				entry["rules"] = []any{"accept"}
				raw, err = json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := DecodeBaseline(raw); err == nil {
				t.Fatal("unsafe source NAT geometry accepted")
			}
		})
	}
}

func TestUplinkNATDynamicAddressingDoesNotInventAnUplinkAddress(t *testing.T) {
	t.Parallel()
	b := uplinkNATBaseline(t)
	b.NetworkModel.UplinkNAT[0].Addresses = []netip.Addr{}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBaseline(raw); err != nil {
		t.Fatal(err)
	}
}
