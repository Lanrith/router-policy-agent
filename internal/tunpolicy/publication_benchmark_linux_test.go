//go:build integration && linux

package tunpolicy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// BenchmarkOwnershipPublication measures rendering, immutable-program inspection
// and a real atomic kernel commit at four qualified addresses per device.
func BenchmarkOwnershipPublication(b *testing.B) {
	if os.Getenv("LANRITH_TUN_INVALIDATION_BENCHMARK") != "isolated" {
		b.Skip("requires an isolated offline root namespace")
	}
	interfaces, err := net.Interfaces()
	if os.Geteuid() != 0 || err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		b.Fatal("benchmark requires an empty isolated namespace")
	}
	read := func(path string) []byte {
		b.Helper()
		data, err := os.ReadFile(path) //nolint:gosec // Fixed compiled synthetic fixture paths only.
		if err != nil {
			b.Fatal(err)
		}
		return data
	}
	executor, err := OpenExecutor(b.Context(), "/usr/sbin/nft", "/usr/sbin/conntrack")
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := executor.Close(); err != nil {
			b.Error(err)
		}
	}()
	guards := read("/compiled/identity-egress.nft")
	for _, match := range regexp.MustCompile(`device "([a-z0-9]+)"`).FindAllSubmatch(guards, -1) {
		command := exec.CommandContext(b.Context(), "/usr/sbin/ip", "link", "add", "dev", string(match[1]), "type", "dummy") //nolint:gosec // Code-owned offline fixture; no host networking is reachable.
		if output, err := command.CombinedOutput(); err != nil {
			b.Fatal(err, string(output))
		}
	}
	for _, program := range [][]byte{read("/compiled/policy.nft"), guards} {
		if _, diagnostic, err := run(b.Context(), executor.nft, string(program), "-f", "-"); err != nil {
			b.Fatal(err, diagnostic)
		}
	}
	listing, _, err := run(b.Context(), executor.nft, "", "-j", "-n", "list", "ruleset")
	if err != nil {
		b.Fatal(err)
	}
	digest, err := ProgramDigest([]byte(listing))
	if err != nil {
		b.Fatal(err)
	}
	baseline, err := policy.DecodeBaseline(read("/compiled/baseline.json"))
	if err != nil {
		b.Fatal(err)
	}
	compiler, err := policy.New(baseline)
	if err != nil {
		b.Fatal(err)
	}
	backend, err := New(baseline, Options{Clock: time.Now, Invalidate: executor.Invalidate,
		Commit: func(ctx context.Context, batch Batch) error {
			started := time.Now()
			if batch.Positive() {
				if err := executor.Inspect(ctx, digest); err != nil {
					b.Logf("inspection failed after %s", time.Since(started))
					return err
				}
			}
			inspected := time.Now()
			err := executor.Commit(ctx, batch)
			if time.Since(started) > 250*time.Millisecond {
				b.Logf("inspection %s commit %s bytes %d: %v", inspected.Sub(started), time.Since(inspected), len(batch.Program()), err)
			}
			return err
		}})
	if err != nil {
		b.Fatal(err)
	}
	for _, devices := range []int{1, 64, 4096} {
		b.Run(fmt.Sprintf("devices=%d", devices), func(b *testing.B) {
			now := time.Now().UTC()
			snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "load-test", ObservedAt: now, Complete: true}
			for i := range devices {
				record := binding.Record{MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256), NAS: "synthetic-switch", Interface: "c6",
					AssociatedAt: now, AssociationID: "fixed-episode"}
				for j := range 4 {
					record.Addresses = append(record.Addresses, binding.Address{
						IP: netip.MustParseAddr(fmt.Sprintf("fd42:1234:5678:10::%x", 16+i*4+j)), Source: "qualified_ipv6",
						OwnershipID: "fixed-lease", ObservedAt: now, ValidUntil: now.Add(time.Minute)})
				}
				snapshot.Records = append(snapshot.Records, record)
			}
			owned, err := compiler.CompileOwnership(b.Context(), snapshot, now, policy.CaptureAge())
			if err != nil {
				b.Fatal(err)
			}
			if err := backend.RefreshOwnership(b.Context(), owned); err != nil {
				b.Fatal("initial publication", err)
			}
			b.ReportAllocs()
			b.ReportMetric(float64(devices*4), "addresses/op")
			for b.Loop() {
				if err := backend.RefreshOwnership(b.Context(), owned); err != nil {
					b.Fatal("publication exceeds its original lifetime budget", err)
				}
			}
		})
	}
}
