//go:build integration && linux

package tunpolicy

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// BenchmarkInvalidation measures the production deletion path with actual
// labelled connections in both families, retaining an unrelated control entry.
func BenchmarkInvalidation(b *testing.B) {
	if os.Getenv("LANRITH_TUN_INVALIDATION_BENCHMARK") != "isolated" {
		b.Skip("requires an isolated offline root namespace")
	}
	interfaces, err := net.Interfaces()
	if os.Geteuid() != 0 || err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		b.Fatal("benchmark requires an empty isolated namespace")
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
	nft := "table inet cleanup_benchmark { chain label { type filter hook forward priority -1; ct label set ct label | 127; }; }\n"
	if _, diagnostic, err := run(b.Context(), executor.nft, nft, "-f", "-"); err != nil {
		b.Fatal(err, diagnostic)
	}
	if _, diagnostic, err := run(b.Context(), executor.conntrack, "", "-I", "-p", "udp", "--orig-src", "198.18.0.10", "--orig-dst", "198.18.0.11", "--sport", "23456", "--dport", "23457", "-t", "300"); err != nil {
		b.Fatal(err, diagnostic)
	}
	for _, size := range []int{1, 256, 16384} {
		b.Run(fmt.Sprintf("connections=%d", size), func(b *testing.B) {
			var commands strings.Builder
			for i := range size {
				source, target := fmt.Sprintf("10.240.%d.%d", i/256, i%256), "10.241.0.2"
				if i%2 == 1 {
					source, target = fmt.Sprintf("fd42:ffff::%x", i), "fd42:eeee::2"
				}
				fmt.Fprintf(&commands, "-I -p udp --orig-src %s --orig-dst %s --sport 12345 --dport 443 -t 60\n", source, target)
			}
			b.ReportAllocs()
			for b.Loop() {
				b.StopTimer()
				if _, diagnostic, err := run(b.Context(), executor.conntrack, commands.String(), "-R", "-"); err != nil {
					b.Fatal("prepare connections", err, diagnostic)
				}
				for _, target := range []string{"10.241.0.2", "fd42:eeee::2"} {
					if size == 1 && strings.Contains(target, ":") {
						continue
					}
					if _, diagnostic, err := run(b.Context(), executor.conntrack, "", "-U", "--orig-dst", target, "--label-add", "lanrith-identity"); err != nil {
						b.Fatal("label connections", err, diagnostic)
					}
				}
				before, _, err := run(b.Context(), executor.conntrack, "", "-L", "--label", "lanrith-identity")
				if err != nil || len(strings.Split(strings.TrimSpace(before), "\n")) != size {
					b.Fatal("missing labelled positive control", err)
				}
				b.StartTimer()
				ctx, cancel := context.WithTimeout(b.Context(), 2*time.Second)
				err = executor.Invalidate(ctx, IdentityConnections)
				cancel()
				b.StopTimer()
				if err != nil {
					b.Fatal("cleanup must finish inside the existing writer budget", err)
				}
				remaining, _, err := run(b.Context(), executor.conntrack, "", "-L")
				if err != nil || len(strings.Split(strings.TrimSpace(remaining), "\n")) != 1 || !strings.Contains(remaining, "src=198.18.0.10 ") {
					b.Fatal("incorrect remaining connection cohort", err, remaining)
				}
				b.StartTimer()
			}
		})
	}
}
