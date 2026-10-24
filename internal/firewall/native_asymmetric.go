package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	nativeAsymmetricTag      = uint64(0xb3000000)
	nativeAsymmetricPriority = "ffff:fb00"
)

type nativeAsymmetricScope struct {
	id                                     uint64
	mode, sourceInterface, targetInterface string
	from, to                               netip.Prefix
}

func (scope nativeAsymmetricScope) predicate(physical bool) nativeScope {
	protocol := "tcp"
	if scope.mode == "icmp_echo_reply" {
		protocol = "icmpv6"
	}
	result := nativeScopePredicate(protocol, 6,
		policy.NetworkSelector{Interface: scope.sourceInterface},
		policy.NetworkSelector{Interface: scope.targetInterface},
		scope.from, scope.to, 0, false, physical)
	if scope.mode == "tcp_dsr" {
		flags := map[string]any{"set": []string{"syn", "ack", "rst"}}
		return nativeJoin(result, nativeMatch("tcp flags & (syn | ack | rst) == ack",
			guardBinary("&", guardPayload("tcp", "flags"), flags), "ack"))
	}
	return nativeJoin(result, nativeMatch("icmpv6 type echo-reply", guardPayload("icmpv6", "type"), "echo-reply"))
}

func (access *nativeAccess) compileAsymmetric(ctx context.Context, b policy.Baseline) error {
	if b.NetworkModel == nil {
		return nil
	}
	for _, reply := range b.NetworkModel.AsymmetricReplies {
		for _, from := range reply.SourceAddresses {
			for _, to := range reply.DestinationAddresses {
				if err := ctx.Err(); err != nil {
					return err
				}
				if len(access.asymmetric) > int(ownershipRuleMask) {
					return errors.New("firewall: asymmetric reply scope capacity exceeded")
				}
				access.asymmetric = append(access.asymmetric, nativeAsymmetricScope{
					id: uint64(len(access.asymmetric)), mode: reply.Mode,
					sourceInterface: reply.SourceInterface, targetInterface: reply.DestinationInterface,
					from: from, to: to,
				})
			}
		}
	}
	if len(access.asymmetric) == 0 {
		return nil
	}
	for _, scope := range access.asymmetric {
		for _, stage := range []string{"guard", "confirm"} {
			chain := fmt.Sprintf("native_asymmetric_%s_%d", stage, scope.id)
			parts := []nativeScope{scope.predicate(false)}
			if stage == "confirm" {
				parts = append(parts, nativeMark(nativeTagMask, nativeAsymmetricTag|scope.id))
			}
			access.add("native_asymmetric_"+stage, nativeJoin(parts...), nativeVerdict("goto", chain))
			access.add(chain, nativeVerdict("jump", "native_raw_floor"))
			access.add(chain, nativeVerdict("jump", "native_forward_floor"))
			access.add(chain, nativeVerdict("jump", "validate_source"))
			if stage == "confirm" {
				access.add(chain, nativeVerdict("jump", "save_owner_priority"))
				access.add(chain, nativeMangle("meta priority set 0xfffffb00", guardMeta("priority"), nativeAsymmetricPriority))
			}
			access.add(chain, nativeMangle("meta mark set meta mark & "+guardMarkKeep,
				guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))),
				nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", nativeAsymmetricTag|scope.id),
					guardMeta("mark"), guardBinary("|", guardMeta("mark"), nativeAsymmetricTag|scope.id)),
				nativeVerdict("accept", ""))
		}
		access.egress[scope.targetInterface] = append(access.egress[scope.targetInterface],
			nativeJoin(nativeMark(nativeTagMask, nativeAsymmetricTag|scope.id),
				nativeMatch("meta priority 0xfffffb00", guardMeta("priority"), nativeAsymmetricPriority),
				scope.predicate(true), nativeVerdict("goto", "restore_owner_priority")))
	}
	access.add("native_asymmetric_guard", nativeVerdict("return", ""))
	access.add("native_asymmetric_confirm", nativeJoin(nativeMark(0xff000000, nativeAsymmetricTag), nativeVerdict("drop", "")))
	access.add("native_asymmetric_confirm", nativeVerdict("return", ""))
	return nil
}
