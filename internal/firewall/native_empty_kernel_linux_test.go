//go:build integration && kernel && linux

package firewall

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestKernelNamedNativeMixedFamilyOnlyPolicy(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	baseline := nativeAccessBaseline(t)
	baseline.NetworkModel.Rules = []policy.NetworkRule{{Action: "deny", Authorization: "inherit", Protocol: "any",
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::10/128")}},
		To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.10/32")}}}}
	layout, err := newNativeAccessLayout(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.freezeInspectionSchemas(ctx); err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created := map[string]bool{}
	for _, match := range regexp.MustCompile(`device "([a-zA-Z0-9_.-]+)"`).FindAllSubmatch(program, -1) {
		name := string(match[1])
		if created[name] {
			continue
		}
		created[name] = true
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	packetNft(ctx, t, string(program))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := process.inspectGuards(ctx, layout); err != nil {
		t.Fatal("mixed-family-only policy did not install its closed native program", err)
	}
	packetNft(ctx, t, "add rule inet "+ownedTable+" native_denies accept")
	if _, err := process.inspectGuards(ctx, layout); err == nil {
		t.Fatal("inspection accepted permission added to an empty deny boundary")
	}
}
