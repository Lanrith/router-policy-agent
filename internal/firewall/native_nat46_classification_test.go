package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/state"
)

func TestNAT46ClassificationClosesBothRepresentationsWithoutMutatingHistory(t *testing.T) {
	t.Parallel()
	baseline := nativeNAT46ModelFixture(t)
	model, err := newNativeNAT46Model(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	history := state.Classification{MACs: []string{"02:00:00:00:00:10"}, IPv4: []string{"10.240.0.10"}, IPv6: []string{model.mappings[0].target.String()}}
	original, err := state.CloneClassification(history)
	if err != nil {
		t.Fatal(err)
	}
	got, err := model.translatedClassification(t.Context(), history)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.240.0.10", model.mappings[0].alias.String()} {
		if !slices.Contains(got.IPv4, address) {
			t.Fatal("real IPv4 or mapped alias lost deny history", address)
		}
		embedded := nativeNAT46SourcePrefix(model.prefix, netip.PrefixFrom(netip.MustParseAddr(address), 32)).Addr().String()
		if !slices.Contains(got.IPv6, embedded) {
			t.Fatal("embedded IPv4 counterpart lost deny history", embedded)
		}
	}
	if len(got.IPv4) != 2 || len(got.IPv6) != 3 || !reflect.DeepEqual(history, original) {
		t.Fatal("projection broadened unrelated identities or changed persisted history")
	}
	again, err := model.translatedClassification(t.Context(), got)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("projection is not idempotent", err)
	}
	baseline.NAT46[0].Alias = netip.MustParseAddr("10.250.0.250")
	baseline.NetworkModel.NAT46Prefix = nil
	immutable, err := model.translatedClassification(t.Context(), history)
	if err != nil || !reflect.DeepEqual(got, immutable) {
		t.Fatal("caller changed compiler-owned classification geometry", err)
	}
	got.IPv4[0] = "10.0.0.1"
	got.MACs[0] = "02:00:00:00:00:11"
	if !reflect.DeepEqual(history, original) {
		t.Fatal("output mutation changed original history")
	}
	empty, err := model.translatedClassification(t.Context(), state.EmptyClassification())
	if err != nil || len(empty.MACs)+len(empty.IPv4)+len(empty.IPv6) != 0 {
		t.Fatal("empty history acquired an identity", err)
	}
}

func TestNAT46ClassificationRestoresInBothFamiliesWithoutPositiveLeases(t *testing.T) {
	t.Parallel()
	model, err := newNativeNAT46Model(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	history := state.Classification{MACs: []string{"02:00:00:00:00:10"}, IPv4: []string{"10.240.0.10"}, IPv6: []string{model.mappings[0].target.String()}}
	shadow, err := model.translatedClassification(t.Context(), history)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := prepareGuardSeal(t.Context(), shadow)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeGuards(t.Context(), mapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(t.Context(), prepared); err != nil {
		t.Fatal("projected history lost typed restoration validation", err)
	}
	var batch guardChanges
	if err := json.Unmarshal(prepared.batch.data, &batch); err != nil {
		t.Fatal(err)
	}
	seen := map[objectReference]int{}
	for _, command := range batch.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Name != cohortSet && element.Name != classified4Set && element.Name != classified6Set {
			t.Fatal("deny-only projection produced positive authority", element.Name)
		}
		seen[objectReference{Family: element.Family, Table: element.Table, Name: element.Name}] += len(element.Values)
	}
	for _, family := range []string{"inet", "netdev"} {
		if seen[objectReference{Family: family, Table: ownedTable, Name: classified4Set}] != len(shadow.IPv4) ||
			seen[objectReference{Family: family, Table: ownedTable, Name: classified6Set}] != len(shadow.IPv6) {
			t.Fatal("restoration omitted a translated deny counterpart", family)
		}
	}
	if len(history.IPv4) != 1 || len(history.IPv6) != 1 {
		t.Fatal("runtime projection changed persisted source history")
	}
}

func TestNAT46ClassificationRejectsMissingHistoryCancellationAndCapacity(t *testing.T) {
	t.Parallel()
	model, err := newNativeNAT46Model(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.translatedClassification(t.Context(), state.Classification{}); err == nil {
		t.Fatal("missing history became explicit empty history")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := model.translatedClassification(ctx, state.EmptyClassification()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	history := state.Classification{MACs: []string{"02:00:00:00:00:10"}, IPv4: []string{"10.240.0.10"}, IPv6: []string{}}
	for index := range 16384 {
		history.IPv6 = append(history.IPv6, fmt.Sprintf("fdca:ffff::%x", index+1))
	}
	slices.Sort(history.IPv6)
	if _, err := state.CloneClassification(history); err != nil {
		t.Fatal("capacity control is invalid", err)
	}
	if _, err := model.translatedClassification(t.Context(), history); err == nil {
		t.Fatal("translated history exceeded fixed classifier capacity")
	}
}
