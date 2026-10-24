package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// This fixture selects only the publication collections on a native skeleton.
// It does not qualify or expose a translated forwarding constructor. The
// original full baseline, compiler geometry and publication proofs stay paired.
func nat46PublicationLayoutFixture(t *testing.T) (*guardLayout, policy.Baseline) {
	t.Helper()
	_, _, _, baseline := nat46TargetGrantFixture(t, true)
	// The publication fixture explicitly delegates both transport protocols
	// between its exact endpoints. The owner-only fixture intentionally cannot
	// be used as delegated authority by the real policy compiler.
	baseline.NetworkModel.Rules[0].Authorization = "directory"
	baseline.NetworkModel.Rules[0].Protocol = "any"
	baseline.NetworkModel.Rules[0].Ports = nil
	baseline.NetworkModel.Rules[0].From[0].MAC = ""
	sources, err := newNativeNAT46StaticSources(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	skeleton, err := policy.DecodeBaseline(raw)
	if err != nil {
		t.Fatal(err)
	}
	skeleton.NAT46, skeleton.NAT46Pools, skeleton.NetworkModel.NAT46Prefix = []policy.NAT46{}, skeleton.NAT46Pools[:0], nil
	layout, err := newNativeAccessLayout(t.Context(), skeleton)
	if err != nil {
		t.Fatal(err)
	}
	layout.native.nat46Sources = sources
	if err := layout.freezeInspectionSchemas(t.Context()); err != nil {
		t.Fatal(err)
	}
	return layout, baseline
}

func TestNAT46PublicationCollectionsRequireExplicitLayoutSelection(t *testing.T) {
	t.Parallel()
	layout, baseline := nat46PublicationLayoutFixture(t)
	if _, err := newNativeAccessLayout(t.Context(), baseline); err == nil {
		t.Fatal("publication plumbing activated unqualified translation")
	}
	for _, family := range []string{"inet", "netdev"} {
		schema, err := layout.schema(family)
		if err != nil {
			t.Fatal(err)
		}
		if schema.sets[nativeNAT46StaticSourceLive] == nil || schema.sets["native_n46_to6_tcp"] == nil || schema.sets[nativeNAT46StaticBindings6] == nil {
			t.Fatal("explicit publication mode omitted a fixed collection", family)
		}
		definitions, err := layout.nat46PublicationDefinitions(t.Context(), family)
		if err != nil || len(definitions) == 0 || bytes.Contains([]byte(definitions[0]), []byte("hook ")) {
			t.Fatal("publication definitions installed a packet hook", err)
		}
	}
	layout.native.nat46Sources = nil
	layout.inspectionSchemas = nil
	for _, family := range []string{"inet", "netdev"} {
		schema, err := layout.schema(family)
		if err != nil || schema.sets[nativeNAT46StaticSourceLive] != nil || schema.sets["native_n46_to6_tcp"] != nil {
			t.Fatal("unselected native mode acquired translation objects", err)
		}
	}
}

func TestNAT46ConfigurationObservationRequiresExactOriginalGeometryAndEpoch(t *testing.T) {
	t.Parallel()
	layout, baseline := nat46PublicationLayoutFixture(t)
	sources := layout.nat46Sources()
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeNAT46Configuration(t.Context(), configurationProofFixture(t, baseline), sources)
	if err != nil {
		t.Fatal(err)
	}
	var batch guardChanges
	if err := json.Unmarshal(prepared.batch.data, &batch); err != nil {
		t.Fatal(err)
	}
	observation := func() *guardTableObservation {
		inet := &guardTableObservation{sets: map[string]listedSet{}}
		for _, command := range batch.Commands {
			if command.Add != nil && command.Add.Element.Family == "inet" {
				inet.sets[command.Add.Element.Name] = listedSet{Elements: append([]json.RawMessage(nil), command.Add.Element.Values...)}
			}
		}
		return inet
	}
	if err := sources.inspectConfigurationChannel(t.Context(), observation()); err != nil {
		t.Fatal("original configuration channel failed observation", err)
	}
	for _, mutation := range []string{"epoch", "source ID", "missing row", "missing epoch", "missing channel", "extra row"} {
		t.Run(mutation, func(t *testing.T) {
			inet := observation()
			switch mutation {
			case "epoch":
				replaceNAT46ListedValue(t, inet, nativeNAT46StaticChannel, `17408`, `18432`)
			case "source ID":
				replaceNAT46ListedValue(t, inet, nativeNAT46StaticChannel, `"0:1"`, `"0:0"`)
			case "missing row":
				set := inet.sets[nativeNAT46StaticChannel]
				set.Elements = set.Elements[1:]
				inet.sets[nativeNAT46StaticChannel] = set
			case "missing epoch":
				inet.sets[configurationEpochSet], inet.sets[configurationEpochMap] = listedSet{}, listedSet{}
			case "missing channel":
				delete(inet.sets, nativeNAT46StaticChannel)
			case "extra row":
				set := inet.sets[nativeNAT46StaticChannel]
				set.Elements = append(set.Elements, set.Elements[0])
				inet.sets[nativeNAT46StaticChannel] = set
			}
			if err := sources.inspectConfigurationChannel(t.Context(), inet); err == nil {
				t.Fatal("changed channel passed observation")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sources.inspectConfigurationChannel(ctx, observation()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled observation continued", err)
	}
}

func TestNAT46LayoutPreparationCannotOmitItsMixedGrantRevocations(t *testing.T) {
	t.Parallel()
	layout, _ := nat46PublicationLayoutFixture(t)
	sealed, err := prepareGuardSeal(t.Context(), state.EmptyClassification())
	if err != nil {
		t.Fatal(err)
	}
	selected, err := prepareLayoutGuards(t.Context(), &preparedBatch{data: clearBatch(t)}, nil, layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	inventory := &guardInventory{native: true, nat46Model: layout.nat46Sources().model}
	// This is the inventory's mode boundary; the complete inventory additionally
	// requires matching logical interfaces and classification on real listings.
	if selected.nat46Model != inventory.nat46Model {
		t.Fatal("mode lost its original immutable model")
	}
	ordinary, err := prepareNativeGuards(t.Context(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkPreparedReplacement(t.Context(), ordinary); err == nil {
		t.Fatal("translated inventory accepted a seal omitting its grants")
	}
	if selected.sourcePublication != nil || !selected.sourceUTC.IsZero() || selected.sourceAnchor != (time.Time{}) {
		t.Fatal("mode selection created positive source authority")
	}
}
