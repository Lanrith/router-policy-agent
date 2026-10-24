package policy

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func coreServiceBaseline(t *testing.T) Baseline {
	t.Helper()
	b, _ := namedFixture(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{ProtectionID: "P03", Networks: prefixes("10.241.254.0/24", "fdca:1a2b:fe02::/64"), Roles: []Role{}})
	b.NetworkModel.CoreServices = []CoreService{{Kind: "dns", Interface: "services0", Addresses: []netip.Addr{netip.MustParseAddr("10.241.254.10"), netip.MustParseAddr("fdca:1a2b:fe02::10")}, Clients: []NetworkSelector{{Interface: "lan13", Addresses: prefixes("10.240.3.0/24", "fdca:1a2b:3::/64")}}}}
	return b
}

func TestCoreServiceContractOwnsItsGeometryWithoutGrantingDirectoryAccess(t *testing.T) {
	t.Parallel()
	b := coreServiceBaseline(t)
	compiler := testCompiler(t, b)
	before := compiler.BaselineHash()
	b.NetworkModel.CoreServices[0].Addresses[0] = netip.MustParseAddr("10.241.254.20")
	b.NetworkModel.CoreServices[0].Clients[0].Addresses[0] = netip.MustParsePrefix("0.0.0.0/0")
	if compiler.BaselineHash() != before {
		t.Fatal("caller mutation changed the immutable core contract")
	}
	_, input := namedFixture(t)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("core declaration changed ordinary delegated scope", candidate.Denials, err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryDNSIsAnExactCoreService(t *testing.T) {
	t.Parallel()
	b := coreServiceBaseline(t)
	b.NetworkModel.CoreServices[0].Kind = "discovery"
	b.NetworkModel.CoreServices[0].Addresses = []netip.Addr{
		netip.MustParseAddr("10.241.254.12"), netip.MustParseAddr("fdca:1a2b:fe02::12"),
	}
	if _, err := New(b); err != nil {
		t.Fatal("bounded discovery DNS rejected", err)
	}
}

func TestCoreServiceContractRejectsUnsafeOrAmbiguousConnectivity(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"other service", "duplicate component", "physical interface", "WAN interface", "unsafe interface", "wrong service link", "empty listeners", "duplicate listener", "unprotected listener", "router listener", "client listener", "mapped IPv6", "unattached client", "WAN client", "wrong client prefix", "empty clients", "empty source prefix", "source MAC", "duplicate client", "missing family"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := coreServiceBaseline(t)
			service := &b.NetworkModel.CoreServices[0]
			switch name {
			case "other service":
				service.Kind = "ssh"
			case "duplicate component":
				b.NetworkModel.CoreServices = append(b.NetworkModel.CoreServices, *service)
			case "physical interface":
				service.Interface = "lan13"
			case "WAN interface":
				service.Interface = "wan"
			case "unsafe interface":
				service.Interface = "svc;accept"
			case "wrong service link":
				other := *service
				other.Kind = "ntp"
				other.Interface = "services1"
				b.NetworkModel.CoreServices = append(b.NetworkModel.CoreServices, other)
			case "empty listeners":
				service.Addresses = nil
			case "duplicate listener":
				service.Addresses = append(service.Addresses, service.Addresses[0])
			case "unprotected listener":
				service.Addresses[0] = netip.MustParseAddr("10.242.254.10")
			case "router listener":
				service.Addresses[0] = netip.MustParseAddr("10.241.0.10")
			case "client listener":
				service.Addresses[0] = netip.MustParseAddr("10.240.3.10")
			case "mapped IPv6":
				service.Addresses[0] = netip.MustParseAddr("::ffff:10.241.254.10")
			case "unattached client":
				service.Clients[0].Interface = "absent"
			case "WAN client":
				service.Clients[0].Interface = "wan"
			case "wrong client prefix":
				service.Clients[0].Addresses[0] = netip.MustParsePrefix("10.240.2.0/24")
			case "empty clients":
				service.Clients = nil
			case "empty source prefix":
				service.Clients[0].Addresses = nil
			case "source MAC":
				service.Clients[0].MAC = "02:00:00:00:00:01"
			case "duplicate client":
				service.Clients = append(service.Clients, service.Clients[0])
			case "missing family":
				service.Addresses = service.Addresses[:1]
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeBaseline(raw); err == nil {
				t.Fatal("unsafe core connectivity accepted")
			}
		})
	}
}

func TestCoreServiceContractRejectsRuntimeFragmentsAndUnknownFields(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"ports", "rules", "authorization", "credential"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(coreServiceBaseline(t))
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]json.RawMessage
			if err := json.Unmarshal(raw, &root); err != nil {
				t.Fatal(err)
			}
			var model map[string]json.RawMessage
			if err := json.Unmarshal(root["network_model"], &model); err != nil {
				t.Fatal(err)
			}
			var services []map[string]json.RawMessage
			if err := json.Unmarshal(model["core_services"], &services); err != nil {
				t.Fatal(err)
			}
			services[0][field] = json.RawMessage(`"untrusted fragment"`)
			model["core_services"], err = json.Marshal(services)
			if err != nil {
				t.Fatal(err)
			}
			root["network_model"], err = json.Marshal(model)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeBaseline(raw); err == nil {
				t.Fatal("core contract accepted runtime rule or credential input")
			}
		})
	}
}

func TestServiceAllocationGeometryStaysSeparateFromDelegationCeilings(t *testing.T) {
	t.Parallel()
	b := coreServiceBaseline(t)
	b.NetworkModel.ServicePrefixes = prefixes("10.241.254.0/24", "fdca:1a2b:fe02::/64")
	compiler := testCompiler(t, b)
	before := compiler.BaselineHash()
	b.NetworkModel.ServicePrefixes[0] = netip.MustParsePrefix("10.0.0.0/8")
	if compiler.BaselineHash() != before {
		t.Fatal("caller changed source allocation geometry")
	}
	_, input := namedFixture(t)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("allocation declaration created or removed a directory capability", err, candidate.Denials)
	}
	for _, test := range []struct {
		name   string
		change func(*Baseline)
	}{
		{"undeclared allocation", func(b *Baseline) { b.NetworkModel.ServicePrefixes[0] = netip.MustParsePrefix("10.242.254.0/24") }},
		{"ordinary attachment", func(b *Baseline) {
			b.NetworkModel.ServicePrefixes[0] = b.Zones[0].Networks[0]
			b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{ProtectionID: "P03", Networks: b.NetworkModel.ServicePrefixes[:1], Roles: []Role{}})
		}},
		{"duplicate", func(b *Baseline) {
			b.NetworkModel.ServicePrefixes = append(b.NetworkModel.ServicePrefixes, b.NetworkModel.ServicePrefixes[0])
		}},
		{"missing component family", func(b *Baseline) { b.NetworkModel.ServicePrefixes = b.NetworkModel.ServicePrefixes[:1] }},
		{"wildcard", func(b *Baseline) { b.NetworkModel.ServicePrefixes[0] = netip.MustParsePrefix("0.0.0.0/0") }},
		{"mapped family", func(b *Baseline) {
			b.NetworkModel.ServicePrefixes[0] = netip.MustParsePrefix("::ffff:10.241.254.0/120")
		}},
		{"noncanonical", func(b *Baseline) { b.NetworkModel.ServicePrefixes[0] = netip.MustParsePrefix("10.241.254.1/24") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			b := coreServiceBaseline(t)
			b.NetworkModel.ServicePrefixes = prefixes("10.241.254.0/24", "fdca:1a2b:fe02::/64")
			test.change(&b)
			if _, err := New(b); err == nil {
				t.Fatal("unsafe service source allocation accepted")
			}
		})
	}
}
