package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/lanrith/router-policy-agent/internal/hostfs"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

const (
	nativeNAT64RuntimeFile      = "runtime.json"
	maximumNAT64RuntimeManifest = 64 << 10
	maximumNAT64RuntimeStatus   = 4 << 10
	maximumNAT64Configuration   = 8 << 20
)

type nativeNAT64RuntimeManifest struct {
	SchemaVersion int                           `json:"schema_version"`
	Components    []nativeNAT64RuntimeComponent `json:"components"`
}

type nativeNAT64RuntimeComponent struct {
	ID                string `json:"id"`
	StatusDirectory   string `json:"status_directory"`
	ConfigurationFile string `json:"configuration_file"`
	Executable        string `json:"executable"`
	Username          string `json:"username"`
	PendingFamily     string `json:"pending_family"`
	PendingTable      string `json:"pending_table"`
	PendingSet        string `json:"pending_set"`
	UID               uint32 `json:"-"`
}

type nativeNAT64RuntimeStatus struct {
	PID                 int     `json:"pid"`
	StartTicks          string  `json:"start_ticks"`
	Monotonic           float64 `json:"monotonic"`
	ConfigurationSHA256 string  `json:"configuration_sha256"`
}

type runtimeNAT64Supervisor struct {
	transports []*nativeNAT64Transport
	components map[string]nativeNAT64RuntimeComponent
}

type runtimeNAT64Readiness struct {
	supervisor          *runtimeNAT64Supervisor
	transport           *nativeNAT64Transport
	entries             []policy.NAT64Allocation
	configurationSHA256 string
}

func loadRuntimeNAT64Supervisor(ctx context.Context, profile *routerProfile, options profileOptions) (*runtimeNAT64Supervisor, error) {
	if ctx == nil || profile == nil || profile.layout == nil || profile.layout.native == nil || !generationHash(options.SHA256) {
		return nil, errors.New("firewall: missing pinned NAT64 runtime manifest dependencies")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("firewall: NAT64 runtime manifest loading requires root")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: options.Directory, OwnerUID: 0, Private: true})
	if err != nil {
		return nil, profileFailure("NAT64 runtime directory unavailable", err)
	}
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{Name: nativeNAT64RuntimeFile, OwnerUID: 0, MaximumSize: maximumNAT64RuntimeManifest})
	if err != nil {
		return nil, profileFailure("NAT64 runtime manifest unavailable", errors.Join(err, root.Close()))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumNAT64RuntimeManifest+1))
	err = errors.Join(readErr, file.Close(), root.Close(), ctx.Err())
	if err != nil {
		return nil, profileFailure("NAT64 runtime manifest read failed", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != options.SHA256 {
		return nil, errors.New("firewall: NAT64 runtime manifest digest mismatch")
	}
	manifest, err := decodeNAT64RuntimeManifest(ctx, data)
	if err != nil {
		return nil, err
	}
	return newRuntimeNAT64Supervisor(ctx, profile.layout.native.selectedNAT64Transports(), manifest)
}

func decodeNAT64RuntimeManifest(ctx context.Context, data []byte) (nativeNAT64RuntimeManifest, error) {
	if ctx == nil || len(data) == 0 || len(data) > maximumNAT64RuntimeManifest {
		return nativeNAT64RuntimeManifest{}, errors.New("firewall: invalid NAT64 runtime manifest")
	}
	if err := strictjson.Object(data, []string{"schema_version", "components"}, nil, maximumNAT64RuntimeManifest); err != nil {
		return nativeNAT64RuntimeManifest{}, profileFailure("NAT64 runtime manifest structure invalid", err)
	}
	var raw struct {
		SchemaVersion int               `json:"schema_version"`
		Components    []json.RawMessage `json:"components"`
	}
	if err := strictjson.Decode(data, &raw, maximumNAT64RuntimeManifest); err != nil || raw.SchemaVersion != 1 || len(raw.Components) == 0 || len(raw.Components) > 4 {
		return nativeNAT64RuntimeManifest{}, errors.New("firewall: invalid NAT64 runtime manifest bounds")
	}
	manifest := nativeNAT64RuntimeManifest{SchemaVersion: raw.SchemaVersion, Components: make([]nativeNAT64RuntimeComponent, 0, len(raw.Components))}
	for _, encoded := range raw.Components {
		if err := ctx.Err(); err != nil {
			return nativeNAT64RuntimeManifest{}, err
		}
		keys := []string{"id", "status_directory", "configuration_file", "executable", "username",
			"pending_family", "pending_table", "pending_set"}
		if err := strictjson.Object(encoded, keys, nil, maximumNAT64RuntimeManifest); err != nil {
			return nativeNAT64RuntimeManifest{}, profileFailure("NAT64 runtime component structure invalid", err)
		}
		var component nativeNAT64RuntimeComponent
		if err := strictjson.Decode(encoded, &component, maximumNAT64RuntimeManifest); err != nil {
			return nativeNAT64RuntimeManifest{}, profileFailure("NAT64 runtime component invalid", err)
		}
		validPaths := helperPath(component.StatusDirectory, 4096) && helperPath(component.ConfigurationFile, 4096) && helperPath(component.Executable, 4096)
		if !interfaceName.MatchString(component.ID) || !nativeNAT64RuntimeUsername(component.Username) || !validPaths ||
			filepath.Dir(component.ConfigurationFile) != component.StatusDirectory ||
			component.PendingFamily != "inet" || component.PendingTable != ownedTable || !nativeNAT64PendingSetName(component.PendingSet) {
			return nativeNAT64RuntimeManifest{}, errors.New("firewall: invalid NAT64 runtime component")
		}
		manifest.Components = append(manifest.Components, component)
	}
	return manifest, ctx.Err()
}

func newRuntimeNAT64Supervisor(ctx context.Context, transports []*nativeNAT64Transport, manifest nativeNAT64RuntimeManifest) (*runtimeNAT64Supervisor, error) {
	if ctx == nil || len(transports) == 0 || len(transports) != len(manifest.Components) || manifest.SchemaVersion != 1 {
		return nil, errors.New("firewall: NAT64 runtime manifest differs from selected components")
	}
	components := make(map[string]nativeNAT64RuntimeComponent, len(manifest.Components))
	for _, component := range manifest.Components {
		if _, duplicate := components[component.ID]; duplicate {
			return nil, errors.New("firewall: duplicate NAT64 runtime component")
		}
		account, err := user.Lookup(component.Username)
		if err != nil || account == nil {
			return nil, errors.New("firewall: NAT64 runtime account unavailable")
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil || uid == 0 {
			return nil, errors.New("firewall: invalid NAT64 runtime account")
		}
		component.UID = uint32(uid) // ParseUint is bounded to 32 bits above.
		components[component.ID] = component
	}
	for _, transport := range transports {
		if transport == nil {
			return nil, errors.New("firewall: NAT64 runtime manifest omitted a selected component")
		}
		component := components[transport.component]
		if component.ID == "" || component.PendingSet != transport.name+"_pending" {
			return nil, errors.New("firewall: NAT64 runtime manifest omitted a selected component")
		}
	}
	return &runtimeNAT64Supervisor{transports: slices.Clone(transports), components: components}, ctx.Err()
}

func nativeNAT64RuntimeUsername(name string) bool {
	if name == "" || len(name) > 32 || name == "root" {
		return false
	}
	for index, character := range name {
		letter := character >= 'a' && character <= 'z'
		suffix := index > 0 && (character >= '0' && character <= '9' || character == '-' || character == '_')
		if !letter && !suffix {
			return false
		}
	}
	return true
}

func nativeNAT64PendingSetName(name string) bool {
	const prefix, suffix = "native_n64_", "_pending"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	index := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	value, err := strconv.ParseUint(index, 10, 2)
	return err == nil && strconv.FormatUint(value, 10) == index
}

func (supervisor *runtimeNAT64Supervisor) activations(ctx context.Context, transports []*nativeNAT64Transport) ([]nativeNAT64Activation, error) {
	if ctx == nil || supervisor == nil || !slices.Equal(supervisor.transports, transports) {
		return nil, errors.New("firewall: NAT64 runtime activation differs from selected profile")
	}
	result := make([]nativeNAT64Activation, 0, len(transports))
	for _, transport := range transports {
		component := supervisor.components[transport.component]
		configuration, err := readNAT64RuntimeFile(ctx, component.StatusDirectory, filepath.Base(component.ConfigurationFile), maximumNAT64Configuration)
		if err != nil {
			return nil, err
		}
		records, err := parseNAT64Configuration(transport, configuration)
		if err != nil {
			return nil, err
		}
		ledger, err := transport.geometry.Capture(ctx, transport.component, nil, records)
		if err != nil {
			return nil, err
		}
		entries, err := ledger.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(configuration)
		proof := &runtimeNAT64Readiness{supervisor: supervisor, transport: transport, entries: entries,
			configurationSHA256: hex.EncodeToString(digest[:])}
		if err := proof.verifyNAT64Readiness(ctx, transport, entries); err != nil {
			return nil, err
		}
		result = append(result, nativeNAT64Activation{Component: transport.component, Ledger: ledger, Readiness: proof})
	}
	return result, ctx.Err()
}

func (proof *runtimeNAT64Readiness) verifyNAT64Readiness(ctx context.Context, transport *nativeNAT64Transport, entries []policy.NAT64Allocation) error {
	if ctx == nil || proof == nil || proof.supervisor == nil || proof.transport != transport ||
		!generationHash(proof.configurationSHA256) || !reflect.DeepEqual(proof.entries, entries) {
		return errors.New("firewall: NAT64 runtime readiness differs from original activation")
	}
	component, found := proof.supervisor.components[transport.component]
	if !found {
		return errors.New("firewall: NAT64 runtime component disappeared")
	}
	statusData, err := readNAT64RuntimeFile(ctx, component.StatusDirectory, "status.json", maximumNAT64RuntimeStatus)
	if err != nil {
		return err
	}
	status, err := decodeNAT64RuntimeStatus(ctx, statusData)
	if err != nil {
		return err
	}
	configuration, err := readNAT64RuntimeFile(ctx, component.StatusDirectory, filepath.Base(component.ConfigurationFile), maximumNAT64Configuration)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(configuration)
	digest := hex.EncodeToString(sum[:])
	if digest != status.ConfigurationSHA256 || digest != proof.configurationSHA256 {
		return errors.New("firewall: NAT64 runtime configuration digest changed")
	}
	if err := verifyNAT64Configuration(transport, entries, configuration); err != nil {
		return err
	}
	if err := verifyNAT64Process(ctx, component, status); err != nil {
		return err
	}
	link, err := net.InterfaceByName(component.ID)
	if err != nil || link.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning {
		return errors.New("firewall: NAT64 translator attachment is not running")
	}
	tunFlags, err := os.ReadFile(filepath.Join("/sys/class/net", component.ID, "tun_flags"))
	if err != nil {
		return errors.New("firewall: NAT64 translator attachment is not a TUN device")
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(string(tunFlags)), 0, 32)
	if err != nil || flags&1 == 0 || flags&2 != 0 {
		return errors.New("firewall: NAT64 translator attachment has invalid TUN flags")
	}
	return ctx.Err()
}

func readNAT64RuntimeFile(ctx context.Context, directory, name string, maximum int64) ([]byte, error) {
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: directory, OwnerUID: 0})
	if err != nil {
		return nil, err
	}
	file, err := hostfs.OpenReadOnlyRegular(ctx, root, hostfs.FileOptions{Name: name, OwnerUID: 0, MaximumSize: maximum})
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	return data, errors.Join(readErr, hostfs.CheckReadOnlyFile(file, 0, maximum), file.Close(), root.Close(), ctx.Err())
}

func decodeNAT64RuntimeStatus(ctx context.Context, data []byte) (nativeNAT64RuntimeStatus, error) {
	keys := []string{"pid", "start_ticks", "monotonic", "configuration_sha256"}
	if ctx == nil || len(data) == 0 || len(data) > maximumNAT64RuntimeStatus || strictjson.Object(data, keys, nil, maximumNAT64RuntimeStatus) != nil {
		return nativeNAT64RuntimeStatus{}, errors.New("firewall: invalid NAT64 runtime status")
	}
	var status nativeNAT64RuntimeStatus
	if err := strictjson.Decode(data, &status, maximumNAT64RuntimeStatus); err != nil || status.PID <= 1 || status.StartTicks == "" ||
		status.Monotonic < 0 || !generationHash(status.ConfigurationSHA256) {
		return nativeNAT64RuntimeStatus{}, errors.New("firewall: invalid NAT64 runtime status")
	}
	uptime, err := os.ReadFile("/proc/uptime")
	fields := strings.Fields(string(uptime))
	if err != nil || len(fields) < 1 {
		return nativeNAT64RuntimeStatus{}, errors.New("firewall: kernel uptime unavailable")
	}
	now, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || now < status.Monotonic || now-status.Monotonic >= 4 {
		return nativeNAT64RuntimeStatus{}, errors.New("firewall: stale NAT64 runtime status")
	}
	return status, ctx.Err()
}

func verifyNAT64Configuration(transport *nativeNAT64Transport, entries []policy.NAT64Allocation, data []byte) error {
	mappings, err := parseNAT64Configuration(transport, data)
	if err != nil {
		return err
	}
	installed := make(map[netip.Addr]netip.Addr, len(mappings))
	for _, mapping := range mappings {
		installed[mapping.Source] = mapping.Alias
	}
	for _, entry := range entries {
		if installed[entry.Source] != entry.Alias {
			return errors.New("firewall: NAT64 runtime omitted an original allocation")
		}
	}
	return nil
}

func parseNAT64Configuration(transport *nativeNAT64Transport, data []byte) ([]policy.NAT64SourceMapping, error) {
	if transport == nil || len(data) == 0 {
		return nil, errors.New("firewall: missing NAT64 runtime configuration")
	}
	mappings := make(map[netip.Addr]netip.Addr)
	aliases := make(map[netip.Addr]bool)
	tun, prefix := "", ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "tun-device":
			if len(fields) != 2 || tun != "" {
				return nil, errors.New("firewall: invalid NAT64 TUN configuration")
			}
			tun = fields[1]
		case "prefix":
			if len(fields) != 2 || prefix != "" {
				return nil, errors.New("firewall: invalid NAT64 prefix configuration")
			}
			prefix = fields[1]
		case "map":
			if len(fields) != 3 {
				return nil, errors.New("firewall: invalid NAT64 mapping configuration")
			}
			alias, aliasErr := netip.ParseAddr(fields[1])
			source, sourceErr := netip.ParseAddr(fields[2])
			if aliasErr != nil || sourceErr != nil || !alias.Is4() || !source.Is6() || aliases[alias] || mappings[source].IsValid() {
				return nil, errors.New("firewall: duplicate or invalid NAT64 runtime mapping")
			}
			aliases[alias], mappings[source] = true, alias
		}
	}
	if tun != transport.component || prefix != transport.prefix.String() {
		return nil, errors.New("firewall: NAT64 runtime configuration differs from selected geometry")
	}
	records := make([]policy.NAT64SourceMapping, 0, len(mappings))
	for source, alias := range mappings {
		records = append(records, policy.NAT64SourceMapping{Source: source, Alias: alias})
	}
	slices.SortFunc(records, func(first, second policy.NAT64SourceMapping) int { return first.Source.Compare(second.Source) })
	return records, nil
}

func verifyNAT64Process(ctx context.Context, component nativeNAT64RuntimeComponent, status nativeNAT64RuntimeStatus) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syscall.Kill(status.PID, 0); err != nil {
		return errors.New("firewall: supervised NAT64 process stopped")
	}
	root := filepath.Join("/proc", strconv.Itoa(status.PID))
	process, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("firewall: supervised NAT64 process identity unavailable")
	}
	defer func() { _ = process.Close() }()
	statData, err := process.ReadFile("stat")
	if err != nil {
		return errors.New("firewall: supervised NAT64 process identity unavailable")
	}
	parts := bytes.SplitN(statData, []byte(") "), 2)
	fields := []string{}
	if len(parts) == 2 {
		fields = strings.Fields(string(parts[1]))
	}
	if len(fields) <= 19 || fields[19] != status.StartTicks {
		return errors.New("firewall: supervised NAT64 process identity changed")
	}
	processStatus, err := process.ReadFile("status")
	if err != nil {
		return errors.New("firewall: supervised NAT64 process status unavailable")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(processStatus), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found {
			values[key] = strings.TrimSpace(value)
		}
	}
	uid := strconv.FormatUint(uint64(component.UID), 10)
	if uidFields := strings.Fields(values["Uid"]); len(uidFields) != 4 || slices.ContainsFunc(uidFields, func(value string) bool { return value != uid }) ||
		strings.TrimLeft(values["CapEff"], "0") != "" {
		return errors.New("firewall: supervised NAT64 process privileges changed")
	}
	commandLine, err := process.ReadFile("cmdline")
	expected := []byte(component.Executable + "\x00--nodetach\x00--config\x00" + component.ConfigurationFile + "\x00")
	if err != nil || !bytes.Equal(commandLine, expected) {
		return errors.New("firewall: supervised NAT64 process command changed")
	}
	executable, err := process.Readlink("exe")
	if err != nil || executable != component.Executable {
		return errors.New("firewall: supervised NAT64 executable changed")
	}
	return ctx.Err()
}

func (manifest nativeNAT64RuntimeManifest) MarshalJSON() ([]byte, error) {
	type plain nativeNAT64RuntimeManifest
	return json.Marshal(plain(manifest))
}
