package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	nativeNAT64TokenTag = uint32(0xa7000000)
	maximumNAT64Tokens  = 65535
)

// nativeNAT64TokenState identifies source connectivity or a selected wire
// authorization. It is produced by the native compiler/publication path, never decoded
// from a deployed manifest or supplied by a policy reader.
type nativeNAT64TokenState struct {
	epoch, context, channel uint32
	origin                  uint32
}

type nativeNAT64TokenEntry struct {
	nativeNAT64TokenState
	token uint32
}

// nativeNAT64Tokens retains its original transport and assigns deterministic
// opaque tokens to complete metadata triples. A token is correlation evidence,
// not permission; every imported packet still undergoes current policy checks.
type nativeNAT64Tokens struct {
	transport *nativeNAT64Transport
	entries   []nativeNAT64TokenEntry
	origin    *nativeNAT64TokenOrigin
	targets   []nativeNAT64TargetEntry
	clear     bool
}

func newNativeNAT64Tokens(ctx context.Context, transport *nativeNAT64Transport, states []nativeNAT64TokenState) (*nativeNAT64Tokens, error) {
	if ctx == nil || transport == nil || transport.geometry == nil || transport.baselineHash == "" || transport.ruleCount < 1 || len(states) == 0 || len(states) > maximumNAT64Tokens {
		return nil, errors.New("firewall: missing or unbounded NAT64 token geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owned := slices.Clone(states)
	slices.SortFunc(owned, compareNAT64TokenState)
	entries := make([]nativeNAT64TokenEntry, 0, len(owned))
	for index, state := range owned {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if index != 0 && sameNAT64TokenKey(state, owned[index-1]) || !validNativeNAT64TokenState(state, transport.ruleCount) {
			return nil, errors.New("firewall: invalid or duplicate NAT64 token state")
		}
		entries = append(entries, nativeNAT64TokenEntry{nativeNAT64TokenState: state, token: nativeNAT64TokenTag | uint32(index+1)}) // #nosec G115 -- count is bounded above.
	}
	return &nativeNAT64Tokens{transport: transport, entries: entries}, ctx.Err()
}

// A zero explicit origin preserves the ordinary same-rule representation.
// Different final rules retain their compiler-derived raw connection marker.
func (state nativeNAT64TokenState) originMarker() uint32 {
	if state.origin != 0 {
		return state.origin
	}
	return state.epoch
}

func sameNAT64TokenKey(first, second nativeNAT64TokenState) bool {
	return first.epoch == second.epoch && first.context == second.context && first.channel == second.channel
}

func compareUint32(first, second uint32) int {
	if first < second {
		return -1
	}
	if first > second {
		return 1
	}
	return 0
}

func validNativeNAT64TokenState(state nativeNAT64TokenState, ruleCount int) bool {
	epochBase := state.epoch & ownershipEpochMask
	rule := state.epoch & ownershipRuleMask
	kind := state.context & 0xff000000
	validKind := false
	for _, expected := range []uint32{0xd1000000, 0xd2000000, 0xd3000000, 0xd4000000, 0xd5000000, 0xd6000000, 0xd7000000, 0xd8000000, 0xd9000000, 0xda000000} {
		validKind = validKind || kind == expected
	}
	origin := state.originMarker()
	target := kind >= 0xd7000000 && kind <= 0xda000000
	return origin&ownershipEpochMask != 0 && origin>>policy.OwnershipRuleBits <= policy.MaximumOwnershipEpoch && ((target && epochBase > origin&ownershipEpochMask) || (!target && origin&ownershipEpochMask == epochBase)) &&
		epochBase != 0 && state.epoch>>policy.OwnershipRuleBits <= policy.MaximumOwnershipEpoch && int(rule) < ruleCount &&
		state.context&^nativeFactsMask == 0 && validKind && state.channel&ownershipEpochMask == epochBase &&
		int(state.originMarker()&ownershipRuleMask) < ruleCount
}

func (tokens *nativeNAT64Tokens) data(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing NAT64 token publication")
	}
	if err := tokens.validate(); err != nil {
		return nil, errors.New("firewall: missing NAT64 token publication")
	}
	operations := make([]any, 0, 8)
	names := tokens.names()
	for _, name := range names {
		kind := "map"
		if tokens.objectKind(name) == "set" {
			kind = "set"
		}
		operations = append(operations, map[string]any{"flush": map[string]any{kind: objectReference{Family: "inet", Table: ownedTable, Name: name}}})
	}
	operations = append(operations, map[string]any{"flush": map[string]any{"map": objectReference{Family: "netdev", Table: ownedTable, Name: tokens.transport.name + "_target_origins"}}})
	operations = append(operations, tokens.transport.tupleProofClears()...)
	if !tokens.clear {
		rows, err := tokens.elements(ctx)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if len(rows[name]) == 0 {
				continue
			}
			operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{
				"family": "inet", "table": ownedTable, "name": name, "elem": rows[name],
			}}})
		}
		origins, err := tokens.targetOriginElements(ctx)
		if err != nil {
			return nil, err
		}
		if len(origins) != 0 {
			operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{"family": "netdev", "table": ownedTable, "name": tokens.transport.name + "_target_origins", "elem": origins}}})
		}

	}
	data, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: NAT64 token publication exceeds its fixed boundary")
	}
	return data, ctx.Err()
}

// publicationData is the privileged writer boundary. Positive rows must be
// rederived from their original compiler-owned access graph, allocation
// ledger, configuration proof and optional verified source publication. The
// raw constructor remains useful for deterministic representation tests but
// cannot make its caller-selected states publishable.
func (tokens *nativeNAT64Tokens) publicationData(ctx context.Context) ([]byte, error) {
	if ctx == nil || tokens == nil {
		return nil, errors.New("firewall: missing NAT64 token publication")
	}
	if tokens.clear {
		if tokens.origin != nil {
			return nil, errors.New("firewall: NAT64 token revocation contains positive authority")
		}
		return tokens.data(ctx)
	}
	if tokens.origin == nil {
		return nil, errors.New("firewall: NAT64 token registry lacks compiler origin")
	}
	expected, err := tokens.origin.derive(ctx)
	if err != nil || expected.transport != tokens.transport || !slices.Equal(expected.entries, tokens.entries) || !slices.Equal(expected.targets, tokens.targets) {
		return nil, errors.New("firewall: NAT64 token registry differs from compiler origin")
	}
	return tokens.data(ctx)
}

func (tokens *nativeNAT64Tokens) names() []string {
	return []string{tokens.transport.name + "_tokens", tokens.transport.name + "_token_epoch", tokens.transport.name + "_token_context", tokens.transport.name + "_token_channel", tokens.transport.name + "_token_origin", tokens.transport.name + "_export_channel", tokens.transport.name + "_target_tokens", tokens.transport.name + "_target_highs", tokens.transport.name + "_token_epoch_pairs"}
}

func (tokens *nativeNAT64Tokens) elements(ctx context.Context) (map[string][]json.RawMessage, error) {
	if ctx == nil || tokens == nil || tokens.clear {
		return nil, errors.New("firewall: missing NAT64 token publication")
	}
	if err := tokens.validate(); err != nil {
		return nil, errors.New("firewall: missing NAT64 token publication")
	}
	names := tokens.names()
	rows := make(map[string][]json.RawMessage, len(names))
	for _, name := range names {
		rows[name] = []json.RawMessage{}
	}
	for _, entry := range tokens.entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		state := entry.nativeNAT64TokenState
		values := []any{
			[]any{map[string]any{"concat": []any{state.epoch, state.context, epochClassID(state.channel)}}, epochClassID(entry.token)},
			[]any{entry.token, state.epoch},
			[]any{entry.token, state.context},
			[]any{entry.token, epochClassID(state.channel)},
			[]any{entry.token, epochClassID(state.originMarker())},
			[]any{epochClassID(entry.token), epochClassID(state.channel)},
			nil, map[string]any{"concat": []any{epochClassID(entry.token), state.context & nativeSourceMask}}, map[string]any{"concat": []any{state.originMarker(), entry.token}},
		}
		for index, value := range values {
			if value == nil {
				continue
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, errors.New("firewall: NAT64 token row encoding failed")
			}
			rows[names[index]] = append(rows[names[index]], encoded)
		}
	}
	targets, err := tokens.targetElements(ctx)
	if err != nil {
		return nil, err
	}
	rows[tokens.transport.name+"_target_tokens"] = targets
	return rows, ctx.Err()
}

func (tokens *nativeNAT64Tokens) validate() error {
	if tokens == nil || tokens.transport == nil || tokens.transport.geometry == nil {
		return errors.New("firewall: missing NAT64 token publication")
	}
	if tokens.clear {
		if len(tokens.entries) != 0 || len(tokens.targets) != 0 {
			return errors.New("firewall: NAT64 token revocation contains positive state")
		}
		return nil
	}
	if len(tokens.entries) == 0 || len(tokens.entries) > maximumNAT64Tokens {
		return errors.New("firewall: invalid NAT64 token count")
	}
	for index, entry := range tokens.entries {
		if !validNativeNAT64TokenState(entry.nativeNAT64TokenState, tokens.transport.ruleCount) ||
			entry.token != nativeNAT64TokenTag|uint32(index+1) || index != 0 && (compareNAT64TokenState(tokens.entries[index-1].nativeNAT64TokenState, entry.nativeNAT64TokenState) >= 0 || sameNAT64TokenKey(tokens.entries[index-1].nativeNAT64TokenState, entry.nativeNAT64TokenState)) { // #nosec G115 -- count is bounded above.
			return errors.New("firewall: changed NAT64 token registry")
		}
	}
	return nil
}

func compareNAT64TokenState(first, second nativeNAT64TokenState) int {
	if first.epoch != second.epoch {
		return compareUint32(first.epoch, second.epoch)
	}
	if first.context != second.context {
		return compareUint32(first.context, second.context)
	}
	if first.channel != second.channel {
		return compareUint32(first.channel, second.channel)
	}
	return compareUint32(first.originMarker(), second.originMarker())
}

func prepareNativeNAT64TokenClear(ctx context.Context, transport *nativeNAT64Transport) (*nativeNAT64Tokens, error) {
	if ctx == nil || transport == nil || transport.geometry == nil {
		return nil, errors.New("firewall: missing NAT64 token revocation geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &nativeNAT64Tokens{transport: transport, clear: true}, nil
}

func (tokens nativeNAT64Tokens) MarshalJSON() ([]byte, error) {
	return nil, errors.New("firewall: original NAT64 token registry cannot be serialized")
}

func (tokens *nativeNAT64Tokens) objectKind(name string) string {
	if name == tokens.transport.name+"_token_epoch_pairs" || name == tokens.transport.name+"_target_highs" {
		return "set"
	}
	return "map"
}
