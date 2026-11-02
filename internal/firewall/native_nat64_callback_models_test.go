package firewall

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNAT64CallbackWriterLayoutFreezesDataWithoutForwardingPermission(t *testing.T) {
	t.Parallel()
	baseline, _, _ := callbackPolicyFixture(t)
	ordinary, err := newNativeNAT64AccessLayout(t.Context(), baseline, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newNativeNAT64CallbackWriterLayout(t.Context(), baseline, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	models, err := nativeNAT64CallbackModels(layout.native.selectedNAT64Transports())
	if err != nil || len(models) != 1 || models[0] != layout.native.nat64Transport.callbacks.grants {
		t.Fatal("writer prototype lost its original selected model", err)
	}
	refs := nativeNAT64CallbackGrantRefs(models)
	if len(refs) != 8 || ordinary.native.nat64Transport.callbacks != nil {
		t.Fatal("prototype changed ordinary admission or lost callback mirrors")
	}
	for _, ref := range refs {
		if slices.Contains(nativeNAT64GrantRefs(), ref) || slices.Contains(nativeNAT46TargetGrantRefs(), ref) {
			t.Fatal("callback data acquired another component's namespace", ref)
		}
		schema, err := layout.schema(ref.Family)
		if err != nil || schema.sets[ref.Name] == nil {
			t.Fatal("callback collection was not frozen before publication", ref, err)
		}
		original, err := ordinary.schema(ref.Family)
		if err != nil || original.sets[ref.Name] != nil {
			t.Fatal("ordinary schema acquired callback objects", ref, err)
		}
	}
	base, err := ordinary.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{"accept", "hook "} {
		if strings.Count(string(base), authority) != strings.Count(string(program), authority) {
			t.Fatal("data-only writer prototype acquired forwarding authority", authority)
		}
	}
}

func TestNAT64CallbackModelSelectionRejectsDetachedAndDuplicateGeometry(t *testing.T) {
	t.Parallel()
	_, callback, model := callbackPolicyFixture(t)
	models, err := nativeNAT64CallbackModels([]*nativeNAT64Transport{callback.native})
	if err != nil || models != nil {
		t.Fatal("tuple-only construction selected a grant writer", err)
	}
	callback.grants = model
	if _, err := nativeNAT64CallbackModels([]*nativeNAT64Transport{callback.native, callback.native}); err == nil {
		t.Fatal("duplicate callback collections accepted")
	}
	for _, test := range []struct {
		name   string
		change func(*nativeNAT64CallbackTransport, *nativeNAT64CallbackModel)
	}{
		{"missing mapped model", func(_ *nativeNAT64CallbackTransport, m *nativeNAT64CallbackModel) { m.mapped = nil }},
		{"foreign namespace", func(_ *nativeNAT64CallbackTransport, m *nativeNAT64CallbackModel) { m.mapped.namespace = "native_n46" }},
		{"changed prefix", func(_ *nativeNAT64CallbackTransport, m *nativeNAT64CallbackModel) {
			m.mapped.prefix = netip.MustParsePrefix("fdca:1a2b:e046::/96")
		}},
		{"changed original callback", func(_ *nativeNAT64CallbackTransport, m *nativeNAT64CallbackModel) { m.callback = nil }},
		{"missing original transport", func(c *nativeNAT64CallbackTransport, _ *nativeNAT64CallbackModel) { c.native = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, callback, model := callbackPolicyFixture(t)
			transport := callback.native
			callback.grants = model
			test.change(callback, model)
			if _, err := nativeNAT64CallbackModels([]*nativeNAT64Transport{transport}); err == nil {
				t.Fatal("detached callback writer model accepted")
			}
		})
	}
}

func TestNAT64CallbackFrozenLayoutRejectsLostOrReplacedSelection(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"lost model", "replaced model", "lost transport", "lost native geometry"} {
		t.Run(mode, func(t *testing.T) {
			baseline, _, _ := callbackPolicyFixture(t)
			layout, err := newNativeNAT64CallbackWriterLayout(t.Context(), baseline, "nat64-internal")
			if err != nil {
				t.Fatal(err)
			}
			original := layout.callbackModels[0]
			switch mode {
			case "lost model":
				original.callback.grants = nil
			case "replaced model":
				changed := *original
				original.callback.grants = &changed
			case "lost transport":
				layout.native.nat64Transport, layout.native.nat64Transports = nil, nil
			case "lost native geometry":
				layout.native = nil
			}
			if _, err := layout.nat64CallbackModels(); err == nil {
				t.Fatal("frozen callback selection was replaced or silently ignored")
			}
			if len(layout.callbackModels) != 1 || layout.callbackModels[0] != original {
				t.Fatal("changed selection rewrote its frozen original")
			}
		})
	}
}
