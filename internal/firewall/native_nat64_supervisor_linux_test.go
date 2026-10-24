package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nat64RuntimeManifestFixture(t *testing.T, transports []*nativeNAT64Transport) nativeNAT64RuntimeManifest {
	t.Helper()
	manifest := nativeNAT64RuntimeManifest{SchemaVersion: 1}
	for index, transport := range transports {
		directory := "/run/lanrith-" + transport.component
		manifest.Components = append(manifest.Components, nativeNAT64RuntimeComponent{
			ID: transport.component, StatusDirectory: directory, ConfigurationFile: directory + "/tayga.conf",
			Executable: "/usr/libexec/lanrith/tayga-" + strconv.Itoa(index), Username: "nobody",
			PendingFamily: "inet", PendingTable: ownedTable, PendingSet: transport.name + "_pending",
		})
	}
	return manifest
}

func encodeNAT64RuntimeManifest(t *testing.T, manifest nativeNAT64RuntimeManifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNAT64RuntimeManifestBindsEverySelectedComponent(t *testing.T) {
	t.Parallel()
	transports := aggregateNAT64StateTransports(t)
	manifest := nat64RuntimeManifestFixture(t, transports)
	data := encodeNAT64RuntimeManifest(t, manifest)
	decoded, err := decodeNAT64RuntimeManifest(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	supervisor, err := newRuntimeNAT64Supervisor(t.Context(), transports, decoded)
	if err != nil || !slicesEqualNAT64Transports(supervisor.transports, transports) {
		t.Fatal("runtime manifest did not retain the exact selected component set", err)
	}

	for _, name := range []string{"missing component", "duplicate component", "extra component", "wrong schema"} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			changed.Components = append([]nativeNAT64RuntimeComponent(nil), manifest.Components...)
			switch name {
			case "missing component":
				changed.Components = changed.Components[:1]
			case "duplicate component":
				changed.Components[1] = changed.Components[0]
			case "extra component":
				changed.Components = append(changed.Components, nativeNAT64RuntimeComponent{ID: "extra"})
			case "wrong schema":
				changed.SchemaVersion = 2
			}
			decoded, decodeErr := decodeNAT64RuntimeManifest(t.Context(), encodeNAT64RuntimeManifest(t, changed))
			if decodeErr == nil {
				_, decodeErr = newRuntimeNAT64Supervisor(t.Context(), transports, decoded)
			}
			if decodeErr == nil {
				t.Fatal("changed runtime component inventory was accepted")
			}
		})
	}
}

func TestNAT64RuntimeManifestRequiresInstalledNonRootAccounts(t *testing.T) {
	t.Parallel()
	transport, _, _ := nat64AllocationFixture(t)
	manifest := nat64RuntimeManifestFixture(t, []*nativeNAT64Transport{transport})
	manifest.Components[0].Username = "lanrith-account-that-does-not-exist"
	if _, err := newRuntimeNAT64Supervisor(t.Context(), []*nativeNAT64Transport{transport}, manifest); err == nil {
		t.Fatal("missing translator account was accepted")
	}
	manifest.Components[0].Username = "root"
	if decoded, err := decodeNAT64RuntimeManifest(t.Context(), encodeNAT64RuntimeManifest(t, manifest)); err == nil || decoded.SchemaVersion != 0 {
		t.Fatal("root translator account produced a usable manifest")
	}
}

func slicesEqualNAT64Transports(first, second []*nativeNAT64Transport) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func TestNAT64RuntimeManifestRejectsUnknownNullAndUnsafeFields(t *testing.T) {
	t.Parallel()
	transport, _, _ := nat64AllocationFixture(t)
	valid := encodeNAT64RuntimeManifest(t, nat64RuntimeManifestFixture(t, []*nativeNAT64Transport{transport}))
	for _, data := range [][]byte{
		{}, []byte(`null`), []byte(`[]`),
		[]byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"yaml":"owner.yaml"`, 1)),
		[]byte(strings.Replace(string(valid), `"username":"nobody"`, `"username":"root"`, 1)),
		[]byte(strings.Replace(string(valid), `"status_directory":"/run/`, `"status_directory":"run/`, 1)),
		[]byte(strings.Replace(string(valid), `"configuration_file":"/run/lanrith-nat64-internal/tayga.conf"`, `"configuration_file":"/etc/tayga.conf"`, 1)),
		[]byte(strings.Replace(string(valid), `"pending_family":"inet"`, `"pending_family":"ip6"`, 1)),
		[]byte(strings.Replace(string(valid), `"pending_table":"router_policy_agent"`, `"pending_table":"lanrith"`, 1)),
		[]byte(strings.Replace(string(valid), `"pending_set":"native_n64_0_pending"`, `"pending_set":"other"`, 1)),
	} {
		if manifest, err := decodeNAT64RuntimeManifest(t.Context(), data); err == nil || manifest.SchemaVersion != 0 {
			t.Fatal("invalid runtime manifest produced usable configuration", string(data))
		}
	}
}

func TestNAT64RuntimeConfigurationRequiresEveryOriginalMapping(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{
		{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true},
		{Source: netip.MustParseAddr("fdca:1a2b::11"), Alias: netip.MustParseAddr("10.251.0.11")},
	}
	transport, err := newNativeNAT64Transport(t.Context(), b, b.NAT64[0].ID)
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
	configuration := []byte("tun-device nat64-internal\nipv4-addr 10.251.0.1\nprefix fdca:1a2b:e064::/96\n" +
		"map 10.251.0.10 fdca:1a2b::10\nmap 10.251.0.11 fdca:1a2b::11\n" +
		"map 10.251.0.12 fdca:1a2b::12\n")
	if err := verifyNAT64Configuration(transport, entries, configuration); err != nil {
		t.Fatal("valid superset runtime mapping inventory rejected", err)
	}
	records, err := parseNAT64Configuration(transport, configuration)
	if err != nil || len(records) != 3 || records[2].Source != netip.MustParseAddr("fdca:1a2b::12") {
		t.Fatal("complete live allocator mapping inventory was not captured", records, err)
	}
	if _, err := transport.geometry.Capture(t.Context(), transport.component, ledger, records); err != nil {
		t.Fatal("complete live allocator mapping inventory did not extend the retained ledger", err)
	}
	for _, changed := range [][]byte{
		[]byte(strings.Replace(string(configuration), "map 10.251.0.10 fdca:1a2b::10\n", "", 1)),
		[]byte(strings.Replace(string(configuration), "map 10.251.0.10 fdca:1a2b::10", "map 10.251.0.12 fdca:1a2b::10", 1)),
		append(append([]byte(nil), configuration...), []byte("map 10.251.0.10 fdca:1a2b::99\n")...),
		[]byte(strings.Replace(string(configuration), "tun-device nat64-internal", "tun-device other", 1)),
	} {
		if err := verifyNAT64Configuration(transport, entries, changed); err == nil {
			t.Fatal("changed NAT64 runtime mapping inventory accepted", string(changed))
		}
	}
}

func TestNAT64RuntimeStatusRequiresFreshKernelMonotonicEvidence(t *testing.T) {
	t.Parallel()
	uptime, err := os.ReadFile("/proc/uptime")
	if err != nil {
		t.Fatal(err)
	}
	now, err := strconv.ParseFloat(strings.Fields(string(uptime))[0], 64)
	if err != nil {
		t.Fatal(err)
	}
	configuration := []byte("synthetic-runtime-configuration")
	sum := sha256.Sum256(configuration)
	valid, err := json.Marshal(nativeNAT64RuntimeStatus{PID: os.Getpid(), StartTicks: "1", Monotonic: now, ConfigurationSHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeNAT64RuntimeStatus(t.Context(), valid); err != nil {
		t.Fatal("fresh strict runtime status rejected", err)
	}
	for _, changed := range [][]byte{
		[]byte(strings.Replace(string(valid), `"pid":`+strconv.Itoa(os.Getpid()), `"pid":1`, 1)),
		[]byte(strings.Replace(string(valid), `"monotonic":`+strconv.FormatFloat(now, 'g', -1, 64), `"monotonic":0`, 1)),
		[]byte(strings.Replace(string(valid), `"configuration_sha256":`, `"yaml":"owner.yaml","configuration_sha256":`, 1)),
	} {
		if _, err := decodeNAT64RuntimeStatus(t.Context(), changed); err == nil {
			t.Fatal("invalid or stale NAT64 runtime status accepted", string(changed))
		}
	}
}
