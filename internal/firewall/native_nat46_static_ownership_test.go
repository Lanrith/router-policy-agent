package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT46SourceGeometryRequiresOriginalOwnershipAndGeometry(t *testing.T) {
	t.Parallel()
	_, publication, _, baseline := nat46TargetGrantFixture(t, true)
	sources, err := newNativeNAT46StaticSources(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := sources.prepareSourceEpoch(t.Context(), publication, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT46StaticOwnership(t.Context(), prepared); err != nil {
		t.Fatal("positive source geometry control rejected", err)
	}
	for _, forbidden := range []string{"lease_", nativeSourceChannel, configurationEpochSet} {
		if bytes.Contains(prepared.batch.data, []byte(forbidden)) {
			t.Fatal("source geometry borrowed a grant, NAS UID or configuration namespace", forbidden)
		}
	}
	if !bytes.Contains(prepared.batch.data, []byte(nativeNAT46StaticSourceChannel)) || !bytes.Contains(prepared.batch.data, []byte("7168")) {
		t.Fatal("source geometry lost its own source-epoch channel")
	}
	for _, name := range []string{"missing geometry", "missing receipt", "other baseline", "wrong epoch", "other map", "changed clock", "changed anchor", "increased lifetime", "clear mode"} {
		t.Run(name, func(t *testing.T) {
			p := *prepared
			switch name {
			case "missing geometry":
				p.geometry = policy.NAT46StaticGeometry{}
			case "missing receipt":
				p.publication = nil
			case "other baseline":
				other := baseline
				other.Generation += "-other"
				different, err := newNativeNAT46StaticSources(t.Context(), other)
				if err != nil {
					t.Fatal(err)
				}
				p.geometry = different.evidence
			case "wrong epoch":
				p.batch.data = bytes.ReplaceAll(p.batch.data, []byte("7168"), []byte("8192"))
			case "other map":
				p.batch.data = bytes.ReplaceAll(p.batch.data, []byte(nativeNAT46StaticSourceChannel), []byte(nativeSourceChannel))
			case "changed clock":
				p.utc = p.utc.Add(time.Second)
			case "changed anchor":
				p.anchor = p.anchor.Add(-time.Second)
			case "increased lifetime":
				p.timeout++
				raw, err := nat46StaticOwnershipChanges(t.Context(), p.geometry, p.publication, p.timeout)
				if err != nil {
					t.Fatal(err)
				}
				p.batch.data = raw
			case "clear mode":
				p.clear = true
			}
			p.digest = sha256.Sum256(p.batch.data)
			if err := validateNAT46StaticOwnership(t.Context(), &p); err == nil {
				t.Fatal("altered source geometry was accepted")
			}
		})
	}
	// A copied older publication may shorten a channel, never renew its epoch.
	aged := *publication
	aged.startedAt = aged.startedAt.Add(-40 * time.Second)
	shorter, err := sources.prepareSourceEpoch(t.Context(), &aged, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if shorter.timeout >= prepared.timeout || validateNAT46StaticOwnership(t.Context(), shorter) != nil {
		t.Fatal("aged source epoch was renewed or lost its positive control")
	}
	stale := *prepared
	stale.publication = &aged
	if err := validateNAT46StaticOwnership(t.Context(), &stale); err == nil {
		t.Fatal("encoded channel exceeded the original publication deadline")
	}
	if err := validateBatch(prepared.batch.data); err == nil {
		t.Fatal("generic grant mutation admitted static source epoch")
	}
	if _, err := sources.prepareSourceEpoch(t.Context(), nil, time.Now().UTC()); err == nil {
		t.Fatal("source geometry supplied an ownership epoch")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := sources.prepareSourceEpoch(ctx, publication, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled source geometry publication continued", err)
	}
}

func TestNAT46SourceGeometryRevocationCannotPublishEvidence(t *testing.T) {
	t.Parallel()
	cleared, err := prepareNAT46StaticOwnershipClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT46StaticOwnership(t.Context(), cleared); err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Commands []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(cleared.batch.data, &batch); err != nil || len(batch.Commands) != 3 || batch.Commands[0]["flush"] == nil {
		t.Fatal("source geometry clear changed more than its fixed channel and mirrors")
	}
	modified := *cleared
	modified.utc = time.Now().UTC()
	if err := validateNAT46StaticOwnership(t.Context(), &modified); err == nil {
		t.Fatal("clear acquired positive metadata")
	}
}

func TestNAT46SourceGeometryHandoffKeepsStaticAndNASNamespacesSeparate(t *testing.T) {
	t.Parallel()
	_, _, _, baseline := nat46TargetGrantFixture(t, true)
	sources, err := newNativeNAT46StaticSources(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []bool{false, true} {
		graph, err := sources.sourceHandoff(t.Context(), nativePacketContext{iface: "lan10", family: 4, id: 17}, directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, rules := range graph {
			for _, rule := range rules {
				if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") || strings.Contains(rule.text, "@"+nativeNAT46StaticChannel) {
					t.Fatal("source handoff gained permission or borrowed configuration", rule.text)
				}
			}
		}
		texts := []string{}
		for _, rules := range graph {
			texts = append(texts, nativeRulesText(rules)...)
		}
		joined := strings.Join(texts, "\n")
		if !strings.Contains(joined, "@"+nativeNAT46StaticSourceChannel) || !strings.Contains(joined, "ip6 saddr @"+classified6Set) || strings.Contains(joined, "ip6 daddr @"+classified6Set) {
			t.Fatal("source handoff confused client history with target NAS ownership")
		}
	}
	for _, reply := range []bool{false, true} {
		rules := nat46StaticSourcePhysical(reply)
		if len(rules) != 4 || rules[len(rules)-1].text != "drop" {
			t.Fatal("source physical predicate lost namespace closure")
		}
		text := strings.Join(nativeRulesText(rules), "\n")
		if !strings.Contains(text, "@ownership_egress_epoch") || strings.Contains(text, "@configuration_egress_epoch") || strings.Contains(text, "accept") {
			t.Fatal("source geometry physical check borrowed a configuration epoch or supplied permission")
		}
	}
	if _, err := sources.sourceHandoff(t.Context(), nativePacketContext{iface: "lan13", family: 4}, false); err == nil {
		t.Fatal("managed NAS source entered static source-epoch geometry")
	}
	if _, err := sources.sourceHandoff(t.Context(), nativePacketContext{iface: "lan10", family: 6}, false); err == nil {
		t.Fatal("native IPv6 source entered IPv4 geometry")
	}
	definition := nat46StaticSourceDefinition()
	if !strings.Contains(definition, "flags timeout") || strings.Contains(definition, "hook") {
		t.Fatal("source channel lacks bounded lifetime or creates a forwarding hook")
	}
}

func TestNAT46SourceTransportAndPolicyRequireMatchingOriginalGeometry(t *testing.T) {
	t.Parallel()
	_, _, _, baseline := nat46TargetGrantFixture(t, true)
	sources, err := newNativeNAT46StaticSources(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newNativeNAT46SourceTransport(t.Context(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if !transport.sourceGeometry {
		t.Fatal("source transport lost its separate namespace")
	}
	for _, authorization := range []string{"owner", "directory"} {
		b := baseline
		b.NetworkModel.Rules = append([]policy.NetworkRule{}, baseline.NetworkModel.Rules...)
		b.NetworkModel.Rules[0].Authorization = authorization
		configured, err := newNativeNAT46StaticSources(t.Context(), b)
		if err != nil {
			t.Fatal(err)
		}
		original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4, id: 17}
		program, err := configured.model.wireSourcePolicy(t.Context(), configured, 0, 0, original, "tcp", false, false)
		if err != nil {
			t.Fatal(err)
		}
		branch := program.chains[program.entry+"_rule_0"]
		expected := 4
		kind := "0xf1000011"
		if authorization == "directory" {
			expected = 5
			kind = "0xf5000011"
		}
		if len(branch) != expected || !strings.Contains(strings.Join(nativeRulesText(branch), "\n"), kind) || branch[len(branch)-1].text != "drop" {
			t.Fatal("source policy lost its authorization namespace or terminal closure")
		}
	}
	other := baseline
	other.Generation += "-other"
	foreign, err := newNativeNAT46StaticSources(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	mixed := *sources
	mixed.model = foreign.model
	if _, err := newNativeNAT46SourceTransport(t.Context(), &mixed); err == nil {
		t.Fatal("source transport combined different root baselines")
	}
	if _, err := sources.model.wireSourcePolicy(t.Context(), foreign, 0, 0, nativePacketContext{iface: "lan10", family: 4}, "tcp", false, false); err == nil {
		t.Fatal("source policy combined different root baselines")
	}
	// Count the entire source/static transport before admitting another mapping.
	mapping := sources.model.mappings[0]
	sources.model.mappings = make([]nativeNAT46Mapping, (nativeRuleCapacity-45)/384)
	for index := range sources.model.mappings {
		sources.model.mappings[index] = mapping
	}
	transport, err = newNativeNAT46SourceTransport(t.Context(), sources)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rules := range transport.chains() {
		count += len(rules)
	}
	if count > nativeRuleCapacity {
		t.Fatal("source transport escaped complete program bound", count)
	}
	sources.model.mappings = append(sources.model.mappings, mapping)
	if _, err := newNativeNAT46SourceTransport(t.Context(), sources); err == nil {
		t.Fatal("source transport did not reject excess mappings before allocation")
	}
}

func nat46SourceChannelObservationFixture(t *testing.T) (*nativeNAT46StaticSources, *guardTableObservation, *guardTableObservation) {
	t.Helper()
	_, publication, _, baseline := nat46TargetGrantFixture(t, true)
	sources, err := newNativeNAT46StaticSources(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := sources.prepareSourceEpoch(t.Context(), publication, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var changes guardChanges
	if err := json.Unmarshal(prepared.batch.data, &changes); err != nil {
		t.Fatal(err)
	}
	inet, netdev := &guardTableObservation{sets: map[string]listedSet{}}, &guardTableObservation{sets: map[string]listedSet{}}
	withExpiry := func(raw json.RawMessage) json.RawMessage {
		var value map[string]map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		timeout, ok := value["elem"]["timeout"].(float64)
		if !ok {
			t.Fatal("source channel observation has no timeout")
		}
		value["elem"]["expires"] = timeout - 1
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, command := range changes.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		observation := inet
		if element.Family == "netdev" {
			observation = netdev
		}
		values := []json.RawMessage{}
		for _, raw := range element.Values {
			if element.Name == nativeNAT46StaticSourceChannel {
				var pair []json.RawMessage
				if err := json.Unmarshal(raw, &pair); err != nil {
					t.Fatal(err)
				}
				pair[0] = withExpiry(pair[0])
				encoded, err := json.Marshal(pair)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, encoded)
			} else {
				values = append(values, withExpiry(raw))
			}
		}
		observation.sets[element.Name] = listedSet{Elements: values}
	}
	epoch, err := json.Marshal(map[string]any{"elem": map[string]any{"val": 7 << 10, "timeout": publication.epochTimeout, "expires": publication.epochTimeout - 1}})
	if err != nil {
		t.Fatal(err)
	}
	inet.sets[ownershipEpochSet] = listedSet{Elements: []json.RawMessage{epoch}}
	return sources, inet, netdev
}

func TestNAT46SourceChannelObservationCannotAdoptEpochIdentityOrDeadline(t *testing.T) {
	t.Parallel()
	sources, inet, netdev := nat46SourceChannelObservationFixture(t)
	if err := sources.inspectSourceEpoch(t.Context(), inet, netdev); err != nil {
		t.Fatal("source channel observation control rejected", err)
	}
	for _, name := range []string{"missing epoch", "changed map epoch", "changed map value", "changed low identity", "missing inet liveness", "missing physical liveness", "longer than epoch"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sources, inet, netdev := nat46SourceChannelObservationFixture(t)
			switch name {
			case "missing epoch":
				inet.sets[ownershipEpochSet] = listedSet{}
			case "changed map epoch":
				entry := inet.sets[nativeNAT46StaticSourceChannel]
				entry.Elements[0] = bytes.ReplaceAll(entry.Elements[0], []byte("7168"), []byte("8192"))
				inet.sets[nativeNAT46StaticSourceChannel] = entry
			case "changed map value":
				entry := inet.sets[nativeNAT46StaticSourceChannel]
				entry.Elements[0] = bytes.ReplaceAll(entry.Elements[0], []byte(`"0:1c01"`), []byte(`"0:2001"`))
				inet.sets[nativeNAT46StaticSourceChannel] = entry
			case "changed low identity":
				entry := netdev.sets[nativeNAT46StaticSourceLive]
				entry.Elements[0] = bytes.ReplaceAll(entry.Elements[0], []byte(`"0:1"`), []byte(`"0:2"`))
				netdev.sets[nativeNAT46StaticSourceLive] = entry
			case "missing inet liveness":
				inet.sets[nativeNAT46StaticSourceLive] = listedSet{}
			case "missing physical liveness":
				netdev.sets[nativeNAT46StaticSourceLive] = listedSet{}
			case "longer than epoch":
				inet.sets[ownershipEpochSet] = listedSet{Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":7168,"timeout":10,"expires":9}}`)}}
			}
			if err := sources.inspectSourceEpoch(t.Context(), inet, netdev); err == nil {
				t.Fatal("modified source channel observation was accepted")
			}
		})
	}
	// Explicitly closed channels are safe with or without a current NAS epoch.
	inet.sets[nativeNAT46StaticSourceChannel] = listedSet{}
	inet.sets[nativeNAT46StaticSourceLive] = listedSet{}
	netdev.sets[nativeNAT46StaticSourceLive] = listedSet{}
	if err := sources.inspectSourceEpoch(t.Context(), inet, netdev); err != nil {
		t.Fatal("closed source channel rejected", err)
	}
	inet.sets[ownershipEpochSet] = listedSet{}
	if err := sources.inspectSourceEpoch(t.Context(), inet, netdev); err != nil {
		t.Fatal("empty source epoch closure rejected", err)
	}
}
