package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT46StaticChannelRequiresBothOriginalOpaqueProofs(t *testing.T) {
	t.Parallel()
	b := nativeNAT46ModelFixture(t)
	sources, err := newNativeNAT46StaticSources(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	proof := configurationProofFixture(t, b)
	prepared, err := sources.prepareConfiguration(t.Context(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT46StaticConfiguration(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(prepared.batch.data, []byte("lease_")) || bytes.Contains(prepared.batch.data, []byte(ownership4Set)) {
		t.Fatal("source geometry minted a NAS binding or directory grant")
	}
	if err := validateBatch(prepared.batch.data); err == nil {
		t.Fatal("generic grant mutation accepted static source publication")
	}
	for _, name := range []string{"epoch", "namespace", "geometry diagnostic", "configuration diagnostic", "baseline", "clear", "clock"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			current, err := sources.prepareConfiguration(t.Context(), proof)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNAT46StaticConfiguration(t.Context(), current); err != nil {
				t.Fatal(err)
			}
			p := *current
			switch name {
			case "epoch":
				p.batch.data = bytes.ReplaceAll(p.batch.data, []byte("17408"), []byte("18432"))
			case "namespace":
				p.batch.data = bytes.ReplaceAll(p.batch.data, []byte(nativeNAT46StaticChannel), []byte(nativeSourceChannel))
			case "geometry diagnostic":
				p.geometry = policy.NAT46StaticGeometry{}
			case "configuration diagnostic":
				p.configuration = policy.OwnerConfiguration{}
			case "baseline":
				other := b
				other.Generation += "-other"
				p.configuration = configurationProofFixture(t, other)
			case "clear":
				p.clear = true
			case "clock":
				p.batch.startedAt = p.batch.startedAt.Add(-preparationBudget)
			}
			p.digest = sha256.Sum256(p.batch.data)
			if err := validateNAT46StaticConfiguration(t.Context(), &p); err == nil {
				t.Fatal("altered channel crossed its typed boundary")
			}
		})
	}
	other := b
	other.Generation += "-other"
	if _, err := sources.prepareConfiguration(t.Context(), configurationProofFixture(t, other)); err == nil {
		t.Fatal("owner configuration transferred to another geometry")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := sources.prepareConfiguration(ctx, proof); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled publication continued", err)
	}
}

func TestNAT46StaticChannelClearCannotPublishState(t *testing.T) {
	t.Parallel()
	p, err := prepareNAT46StaticConfigurationClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT46StaticConfiguration(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Operations []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(p.batch.data, &batch); err != nil || len(batch.Operations) != 1 || batch.Operations[0]["flush"] == nil {
		t.Fatal("revocation can add positive state", err)
	}
	p.configuration = configurationProofFixture(t, nativeNAT46ModelFixture(t))
	if err := validateNAT46StaticConfiguration(t.Context(), p); err == nil {
		t.Fatal("revocation carried positive owner evidence")
	}
}

func TestNAT46StaticFactsCannotBecomeASourceOrPermission(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"inet", "netdev"} {
		definitions, err := sources.definitions(t.Context(), family)
		if err != nil || len(definitions) == 0 {
			t.Fatal("missing static identity definitions", err)
		}
		if bytes.Contains([]byte(strings.Join(definitions, "\n")), []byte("hook ")) {
			t.Fatal("source geometry installed a hook")
		}
	}
	chains, err := sources.handoff(t.Context(), nativePacketContext{iface: "lan10", family: 4})
	if err != nil {
		t.Fatal(err)
	}
	for _, rules := range chains {
		for _, rule := range rules {
			if strings.Contains(rule.text, "accept") {
				t.Fatal("geometry handoff granted traffic")
			}
		}
	}
	for _, reply := range []bool{false, true} {
		for _, rule := range nat46StaticPhysical(reply) {
			if strings.Contains(rule.text, "accept") {
				t.Fatal("source fact check granted traffic")
			}
		}
	}
	if _, err := sources.handoff(t.Context(), nativePacketContext{iface: "wan", family: 4}); err == nil {
		t.Fatal("source borrowed another interface's geometry")
	}
	if _, err := sources.handoff(t.Context(), nativePacketContext{iface: "lan10", family: 6}); err == nil {
		t.Fatal("IPv6 source entered IPv4 alias geometry")
	}
}

func TestNAT46StaticInventoryRejectsChangedIdentityRows(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"inet", "netdev"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			_, rows, err := sources.staticInventory(t.Context(), family)
			if err != nil {
				t.Fatal(err)
			}
			observation := func() *guardTableObservation {
				observed := &guardTableObservation{sets: map[string]listedSet{}}
				for name, elements := range rows {
					observed.sets[name] = listedSet{Elements: slices.Clone(elements)}
				}
				return observed
			}
			if err := sources.inspectStaticIdentities(t.Context(), family, observation()); err != nil {
				t.Fatal(err)
			}
			for name, elements := range rows {
				for _, mutation := range []string{"missing object", "missing row", "duplicate row", "changed row"} {
					t.Run(name+"/"+mutation, func(t *testing.T) {
						t.Parallel()
						observed := observation()
						if len(elements) == 0 {
							t.Fatal("fixture did not exercise an identity")
						}
						switch mutation {
						case "missing object":
							delete(observed.sets, name)
						case "missing row":
							observed.sets[name] = listedSet{Elements: elements[1:]}
						case "duplicate row":
							observed.sets[name] = listedSet{Elements: append(slices.Clone(elements), elements[0])}
						case "changed row":
							changed := slices.Clone(elements)
							changed[0] = json.RawMessage(`{"concat":[0,"0:2","fdca:1a2b:e046::af0:a"]}`)
							observed.sets[name] = listedSet{Elements: changed}
						}
						if err := sources.inspectStaticIdentities(t.Context(), family, observed); err == nil {
							t.Fatal("changed permanent identity was accepted")
						}
					})
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := sources.inspectStaticIdentities(ctx, family, observation()); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled identity inspection continued", err)
			}
		})
	}
}

func TestNAT46StaticInventoryEmptyGeometryAndInvalidInputs(t *testing.T) {
	t.Parallel()
	b := nativeNAT46ModelFixture(t)
	b.NetworkModel.Rules[0].Action = "deny"
	sources, err := newNativeNAT46StaticSources(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"inet", "netdev"} {
		definitions, err := sources.definitions(t.Context(), family)
		if err != nil || strings.Contains(strings.Join(definitions, "\n"), "elements={}") {
			t.Fatal("empty geometry generated an empty element declaration", err)
		}
		_, rows, err := sources.staticInventory(t.Context(), family)
		if err != nil {
			t.Fatal(err)
		}
		observed := &guardTableObservation{sets: map[string]listedSet{}}
		for name, elements := range rows {
			if len(elements) != 0 {
				t.Fatal("deny rule generated a source identity")
			}
			observed.sets[name] = listedSet{}
		}
		if err := sources.inspectStaticIdentities(t.Context(), family, observed); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := sources.staticInventory(t.Context(), "bridge"); err == nil {
		t.Fatal("unknown family entered static identity inventory")
	}
	if _, _, err := sources.staticInventory(nil, "inet"); err == nil { //nolint:staticcheck // Deliberately verify rejection of a missing context.
		t.Fatal("missing context entered static identity inventory")
	}
	if err := sources.inspectStaticIdentities(t.Context(), "inet", nil); err == nil {
		t.Fatal("missing observation entered static identity inventory")
	}
}
