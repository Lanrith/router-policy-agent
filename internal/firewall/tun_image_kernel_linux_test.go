//go:build integration && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/agent"
	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/ipc"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// The runner installs the platform's compiled synthetic program in an offline
// namespace. No owner YAML or Python compiler is available to the runtime.
func TestTUNImageProfileRecovery(t *testing.T) {
	fixture := os.Getenv("LANRITH_TUN_IMAGE_FIXTURE")
	if fixture == "" {
		t.Skip("requires the isolated platform TUN image fixture")
	}
	if os.Geteuid() != 0 || fixture != "/compiled" {
		t.Fatal("requires the fixed isolated root fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(fixture, name)) //nolint:gosec // Fixed synthetic fixture and code-owned filenames in the isolated runner.
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	nft := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/sbin/nft", args...) //nolint:gosec // Test-only, fixed nft operations in an explicitly isolated namespace.
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("nft: %v: %s", err, output)
		}
		return output
	}
	// The build compiler freezes the expected program before the runtime opens
	// its profile. Subsequent kernel mutations cannot replace this independent pin.
	artifacts, err := BuildTUNImageProfile(ctx, read("baseline.json"),
		nft("-j", "-n", "list", "ruleset"), read("identity-egress.nft"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Profile string `json:"profile_sha256"`
		Floor   string `json:"floor_sha256"`
	}
	if err := json.Unmarshal(artifacts.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, name := range []string{"profile", "generation", "state"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := helperConfigFixture()
	config.Backend, config.ConntrackExecutable = "tun", "/usr/sbin/conntrack"
	config.NFTExecutable = "/usr/sbin/nft"
	config.Profile = helperProfile{Directory: filepath.Join(root, "profile"), SHA256: metadata.Profile}
	config.GenerationDir, config.StateDir = filepath.Join(root, "generation"), filepath.Join(root, "state")
	config.ExpectedGeneration.FloorHash = metadata.Floor
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(config.Profile.Directory, "profile.json"), bytes.TrimSuffix(artifacts.Profile, []byte{'\n'}))
	generation, err := json.Marshal(config.ExpectedGeneration)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(config.GenerationDir, writerGenerationFile), generation)
	if err := initializeTUNState(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err := recoverTUN(ctx, config); err != nil {
		t.Fatal(err)
	}
	assertStarted := func(open bool) {
		t.Helper()
		data := nft("-j", "list", "set", "inet", "lanrith", "tp_started")
		var listing struct {
			Objects []struct {
				Set *struct {
					Elements []json.RawMessage `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(data, &listing); err != nil {
			t.Fatal(err)
		}
		for _, object := range listing.Objects {
			if object.Set != nil {
				if (len(object.Set.Elements) == 1) != open {
					t.Fatalf("startup gate open=%v: %s", open, data)
				}
				return
			}
		}
		t.Fatal("startup set missing")
	}
	assertStarted(false)
	for _, stage := range []string{"first start", "restart"} {
		t.Run(stage, func(t *testing.T) {
			resources, err := openTUNResources(ctx, config, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := resources.close(ctx); err != nil {
					t.Error(err)
				}
			}()
			if stage == "first start" {
				document, err := resources.store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				compiler, err := policy.New(resources.baseline)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				snapshot := policy.DirectorySnapshot{ObservedAt: now, Complete: true,
					Devices: []policy.Device{{ID: "known-inactive", MAC: "02:00:00:00:04:02", GroupIDs: []string{}}},
					Groups:  []policy.Group{}}
				ledger, err := compiler.ObserveDirectory(ctx, snapshot, now, document.Ledger)
				if err != nil {
					t.Fatal(err)
				}
				document, err = state.Advance(document, snapshot, ledger)
				if err != nil {
					t.Fatal(err)
				}
				document, err = state.RememberAddresses(document, []netip.Addr{netip.MustParseAddr("10.240.40.2")})
				if err != nil {
					t.Fatal(err)
				}
				if err := resources.store.Save(ctx, document); err != nil {
					t.Fatal(err)
				}
			}
			engine, err := agent.New(resources.baseline, agent.Options{Mode: agent.Enforce,
				Clock: time.Now, State: agent.Persistence{Load: resources.store.Load,
					Save: resources.store.Save, AdvanceOwnershipEpoch: resources.store.AdvanceOwnershipEpoch},
				Bindings: func(context.Context) (binding.Snapshot, error) {
					return binding.Snapshot{SchemaVersion: 1, Generation: "empty-current",
						ObservedAt: time.Now().UTC(), Complete: true}, nil
				}, Firewall: resources.backend.Enforcement()})
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.Start(ctx); err != nil {
				t.Fatal(err)
			}
			assertStarted(true)
			for _, table := range []struct{ family, name string }{{"inet", "lanrith"}, {"netdev", "lanrith_identity"}} {
				if !bytes.Contains(nft("list", "set", table.family, table.name, "tp_history4"), []byte("10.240.40.2")) {
					t.Fatal("startup did not restore persistent classification", table)
				}
			}
			if err := resources.executor.Inspect(ctx, metadata.Floor); err != nil {
				t.Fatal(err)
			}
			// An unprivileged directory proposal cannot change the program. A
			// privileged drift here simulates a broken local image invariant.
			nft("add", "chain", "inet", "lanrith", "unexpected_program")
			compiler, err := policy.New(resources.baseline)
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := compiler.CompileOwnerConfiguration(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := resources.backend.RefreshConfiguration(ctx, configuration); err == nil {
				t.Fatal("positive publication accepted a changed kernel program")
			}
			if err := engine.Stop(ctx); err != nil {
				t.Fatal("negative shutdown must remain possible after drift", err)
			}
			assertStarted(false)
			nft("delete", "chain", "inet", "lanrith", "unexpected_program")
		})
	}
	exerciseTUNIPC(ctx, t, config, nft)
	assertStarted(false)
	// Recovery must not manufacture an empty history after storage corruption.
	write(filepath.Join(config.StateDir, "state.json"), []byte("corrupt\n"))
	if err := recoverTUN(ctx, config); err == nil {
		t.Fatal("corrupt persistent state was accepted or reinitialized")
	}
	assertStarted(false)
	if data, err := os.ReadFile(filepath.Join(config.StateDir, "state.json")); err != nil || string(data) != "corrupt\n" {
		t.Fatal("recovery changed corrupt evidence", err)
	}
}

// exerciseTUNIPC uses the actual configured service, persistent store and peer
// credentials. Only the directory reader UID may propose snapshots; the distinct
// operator UID can inspect status but cannot write grants.
func exerciseTUNIPC(ctx context.Context, t *testing.T, config helperConfig, nft func(...string) []byte) {
	t.Helper()
	t.Setenv("NOTIFY_SOCKET", "")
	root, err := os.MkdirTemp("/run", "tun-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(root, 0o755); err != nil { //nolint:gosec // Test socket metadata inspection only; profile and state remain in separate private directories.
		t.Fatal(err)
	}
	listener := func(name string) *net.UnixListener {
		t.Helper()
		path := filepath.Join(root, name)
		value, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		value.SetUnlinkOnClose(false)
		if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // Synthetic shared group permits reaching the socket; SO_PEERCRED authorizes the UID.
			t.Fatal(err)
		}
		return value
	}
	requests, status := listener("requests.sock"), listener("status.sock")
	observations := listener("observations.sock")
	config.ObserverUID = 65532
	ready := make(chan struct{})
	var once sync.Once
	var observed time.Time
	options := configuredOptions{requests: requests, status: status, observations: observations, bindings: func(context.Context) (binding.Snapshot, error) {
		once.Do(func() { observed = time.Now().UTC(); close(ready) })
		return binding.Snapshot{SchemaVersion: 1, Generation: "ipc-binding", ObservedAt: time.Now().UTC(), Complete: true,
			Records: []binding.Record{{MAC: "02:00:00:00:04:02", NAS: "synthetic-switch", Interface: "c4", AssociatedAt: observed, AssociationID: "ipc-association",
				Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.40.2"), Source: "kea_dhcp4", OwnershipID: "ipc-lease", ObservedAt: observed, ValidUntil: observed.Add(time.Minute)}}}}}, nil
	}}
	serving, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { finished <- runTUNService(serving, options, config, time.Now) }()
	defer func() {
		stop()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Errorf("configured service shutdown: %v", err)
		}
		for _, endpoint := range []*net.UnixListener{requests, status, observations} {
			if _, err := os.Lstat(endpoint.Addr().String()); err != nil {
				t.Errorf("shutdown removed supervisor socket: %v", err)
			}
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("configured service did not initialize bindings")
	}
	placement := `{"schema_version":1,"kind":"placement","vlan_role":"four"}`
	access := `{"schema_version":1,"kind":"access","vlan_role":"four","temporary":false,"rules":[{"id":"callback","direction":"to_device","peer":{"addresses":["fd42:1234:5678:20::10/128"]},"protocol":"udp","destination_ports":[22222],"reason":"synthetic callback"}]}`
	snapshot := policy.DirectorySnapshot{ObservedAt: time.Now().UTC(), Complete: true,
		Groups:  []policy.Group{{ID: "placement", Name: "Devices", Policy: &placement, IsNetwork: true}, {ID: "access", Name: "Callbacks", Policy: &access, IsNetwork: true}},
		Devices: []policy.Device{{ID: "known-inactive", MAC: "02:00:00:00:04:02", Active: true, GroupIDs: []string{"placement", "access"}}}}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client := func(uid uint32, endpoint, operation, expected string) {
		t.Helper()
		data, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, executable, "-test.run=^TestTUNIPCClient$")
		command.Env = []string{"LANRITH_TUN_IPC_CHILD=1", "LANRITH_TUN_IPC_SOCKET=" + endpoint,
			"LANRITH_TUN_IPC_OPERATION=" + operation, "LANRITH_TUN_IPC_EXPECT=" + expected}
		command.Stdin = bytes.NewReader(data)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: 0, NoSetGroups: true}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("IPC uid=%d %s %s: %v: %s", uid, operation, expected, err, output)
		}
	}
	for _, uid := range []uint32{0, 65532, config.OperatorUID} {
		client(uid, requests.Addr().String(), "submit", "rejected")
	}
	client(config.ReaderUID, status.Addr().String(), "status", "rejected")
	client(config.ReaderUID, requests.Addr().String(), "submit", "applied")
	assertGrants := func(present bool) {
		t.Helper()
		if bytes.Contains(nft("list", "set", "inet", "lanrith", "tp_grants4"), []byte("22222")) != present {
			t.Fatal("authenticated request did not produce the expected grant state")
		}
	}
	assertGrants(true)
	client(config.OperatorUID, status.Addr().String(), "status", "ready")
	client(config.ReaderUID, observations.Addr().String(), "observations", "rejected")
	client(config.ObserverUID, observations.Addr().String(), "observations", "ready")
	// Identical current observations are idempotent; they retain their original
	// deadline. An older observation cannot undo a subsequent revocation.
	client(config.ReaderUID, requests.Addr().String(), "submit", "applied")
	originalObservation := snapshot.ObservedAt
	snapshot.ObservedAt = time.Now().UTC()
	snapshot.Devices[0].Active = false
	client(config.ReaderUID, requests.Addr().String(), "submit", "denied")
	assertGrants(false)
	snapshot.ObservedAt = originalObservation
	snapshot.Devices[0].Active = true
	client(config.ReaderUID, requests.Addr().String(), "submit", "rejected")
	assertGrants(false)
	snapshot.ObservedAt = time.Now().UTC()
	client(config.ReaderUID, requests.Addr().String(), "submit", "applied")
	assertGrants(true)
	snapshot.ObservedAt = time.Now().UTC()
	snapshot.Devices[0].Active = false
	client(config.ReaderUID, requests.Addr().String(), "submit", "denied")
	assertGrants(false)
}

func TestTUNIPCClient(t *testing.T) {
	if os.Getenv("LANRITH_TUN_IPC_CHILD") != "1" {
		t.Skip("isolated subprocess entry point")
	}
	options := ipc.ClientOptions{Socket: os.Getenv("LANRITH_TUN_IPC_SOCKET"), ServerUID: 0, Timeout: 2 * time.Second}
	expected := os.Getenv("LANRITH_TUN_IPC_EXPECT")
	if os.Getenv("LANRITH_TUN_IPC_OPERATION") == "observations" {
		err := readTUNObservation(t.Context(), options.Socket)
		if (err != nil) != (expected == "rejected") {
			t.Fatal("observer identity or response differs", err)
		}
		return
	}
	if os.Getenv("LANRITH_TUN_IPC_OPERATION") == "status" {
		report, err := ipc.ReadStatus(t.Context(), options)
		if expected == "rejected" {
			if err == nil {
				t.Fatal("unauthorized status reader accepted")
			}
		} else if err != nil || report.FloorState != "matches_pinned_contract" || report.KernelTupleCount == nil || *report.KernelTupleCount == 0 {
			t.Fatal("operator status failed", err, report.FloorState)
		}
		return
	}
	var snapshot policy.DirectorySnapshot
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 16<<20)).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	receipt, err := ipc.Submit(t.Context(), options, snapshot)
	if expected == "rejected" {
		if err == nil || receipt.GrantCount != 0 {
			t.Fatal("unauthorized or replayed request accepted")
		}
		return
	}
	if err != nil || receipt.Status != ipc.StatusApplied || (receipt.GrantCount > 0) != (expected == "applied") {
		t.Fatalf("unexpected receipt %+v: %v", receipt, err)
	}
}

func readTUNObservation(ctx context.Context, path string) error {
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	const request = `{"schema_version":1,"operation":"observations","generation":"","offset":0}`
	frame := append([]byte{0, 0, 0, byte(len(request))}, request...)
	if _, err := connection.Write(frame); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 512<<10 {
		return errors.New("invalid observation frame size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(connection, data); err != nil {
		return err
	}
	var response ipc.ObservationResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}
	if response.Code != "" || response.Snapshot == nil || response.Snapshot.Total == 0 {
		return errors.New("missing current observation snapshot")
	}
	return nil
}
