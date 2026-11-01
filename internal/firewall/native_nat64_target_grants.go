package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Target grants retain the exact IPv4 device and its original IPv6 caller.
// The compiler's reviewed source mapping supplies the wire alias; an arbitrary
// address inside a translator pool cannot become that caller's identity.
func (transport *nativeNAT64Transport) projectTargetValues(ctx context.Context, logical guardChanges, publication *nativeSourcePublication, utc, anchor time.Time) (map[string]map[string]int, error) {
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	ids := nativeNAT64AddressIDs(snapshot, false)
	indexes := map[nativeSourceIP]int{}
	for index, address := range snapshot.Addresses {
		if address.Address.Is4() {
			indexes[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}] = index
		}
	}
	callers := map[netip.Addr]netip.Addr{}
	for _, mapping := range transport.mappings {
		if mapping.Ready {
			callers[mapping.Alias] = mapping.Source
		}
	}
	values := map[string]map[string]int{}
	for _, command := range logical.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "inet" || element.Table != ownedTable || element.Name != "lease_to4_tcp" && element.Name != "lease_to4_udp" {
			continue
		}
		protocol := "tcp"
		if element.Name == "lease_to4_udp" {
			protocol = "udp"
		}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, true)
			if err != nil {
				return nil, err
			}
			identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: tuple.interfaceName, mac: tuple.mac}, address: tuple.device}
			id, known := ids[identity]
			index, published := indexes[identity]
			caller, mapped := callers[tuple.peer]
			if !known || !published || !mapped {
				continue
			}
			remaining, err := publication.remaining(ctx, index, anchor)
			if err != nil {
				continue
			}
			proofRemaining, err := publication.evidence.Remaining(index, utc)
			if err != nil {
				continue
			}
			timeout := int((min(remaining, proofRemaining) - preparationBudget - commandBudget) / time.Second)
			var lease struct {
				Element struct {
					Timeout int `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &lease); err != nil {
				return nil, err
			}
			timeout = min(timeout, lease.Element.Timeout)
			if timeout < 1 {
				continue
			}
			channel := snapshot.Epoch<<policy.OwnershipRuleBits | id&ownershipRuleMask
			high := (id >> policy.OwnershipRuleBits) << 13
			for _, version := range []int{4, 6} {
				peer := tuple.peer
				if version == 6 {
					peer = caller
				}
				key, err := json.Marshal(map[string]any{"concat": []any{epochClassID(channel), high, peer.String(), tuple.port}})
				if err != nil {
					return nil, err
				}
				name := fmt.Sprintf("native_n64_to%d_%s", version, protocol)
				if values[name] == nil {
					values[name] = map[string]int{}
				}
				values[name][string(key)] = max(values[name][string(key)], timeout)
				if len(values[name]) > maximumTupleCount {
					return nil, errors.New("firewall: NAT64 target grants exceed capacity")
				}
			}
		}
	}
	return values, ctx.Err()
}

func nativeNAT64TargetGrant(leg nativeNAT64Leg, imported bool) (nativeScope, bool) {
	if leg.protocol != "tcp" && leg.protocol != "udp" {
		return nativeScope{}, false
	}
	family, version := "ip6", 6
	if leg.reply != imported {
		family, version = "ip", 4
	}
	peer, port := "saddr", "dport"
	if leg.reply {
		peer, port = "daddr", "sport"
	}
	name := fmt.Sprintf("native_n64_to%d_%s", version, leg.protocol)
	key := map[string]any{"concat": []any{guardMeta("priority"), guardBinary("&", guardMeta("mark"), nativeSourceMask), guardPayload(family, peer), guardPayload(leg.protocol, port)}}
	return nativeMatch(fmt.Sprintf("meta priority . (meta mark & 0xe000) . %s %s . %s %s @%s", family, peer, leg.protocol, port, name), key, "@"+name), true
}
