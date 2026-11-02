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

type nativeNAT64OwnedCaller struct {
	index int
	id    uint32
}

type nativeNAT64RecipientGrant struct {
	caller   nativeNAT64OwnedCaller
	epoch    uint32
	target   netip.Addr
	protocol string
	port     uint16
	timeout  int
}

// A recipient's exact listener grant can authorize an independently owned
// caller. Retain that caller's canonical IPv6 UID; clip the projection to both
// original ownership deadlines and the already clipped recipient grant.
func (transport *nativeNAT64Transport) projectRecipientValues(ctx context.Context, publication *nativeSourcePublication, utc, anchor time.Time, grant nativeNAT64RecipientGrant, values map[string]map[string]int) error {
	if grant.caller.id == 0 {
		return errors.New("firewall: NAT64 recipient grant lost its caller identity")
	}
	remaining, err := publication.remaining(ctx, grant.caller.index, anchor)
	if err != nil {
		return ctx.Err()
	}
	proof, err := publication.evidence.Remaining(grant.caller.index, utc)
	if err != nil {
		return ctx.Err()
	}
	timeout := min(grant.timeout, int((min(remaining, proof)-preparationBudget-commandBudget)/time.Second))
	if timeout < 1 {
		return ctx.Err()
	}
	channel := grant.epoch<<policy.OwnershipRuleBits | grant.caller.id&ownershipRuleMask
	high := (grant.caller.id >> policy.OwnershipRuleBits) << 13
	encoded := transport.prefix.Addr().As16()
	address := grant.target.As4()
	copy(encoded[12:], address[:])
	for _, version := range []int{4, 6} {
		peer := grant.target
		if version == 6 {
			peer = netip.AddrFrom16(encoded)
		}
		key, err := json.Marshal(map[string]any{"concat": []any{epochClassID(channel), high, peer.String(), grant.port}})
		if err != nil {
			return err
		}
		name := fmt.Sprintf("native_n64_from%d_%s", version, grant.protocol)
		if values[name] == nil {
			values[name] = map[string]int{}
		}
		values[name][string(key)] = max(values[name][string(key)], timeout)
		if len(values[name]) > maximumTupleCount {
			return errors.New("firewall: NAT64 recipient grant capacity exceeded")
		}
	}
	return ctx.Err()
}
