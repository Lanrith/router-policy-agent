package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Callback policies retain the original owner graph and distinct component
// namespace. These construction-only predicates install no hooks or grants.
// The caller must still join original allocation/readiness, current ownership,
// exact tuple correlation, mandatory guards and current listener grants on all
// four legs and at physical egress. Default profiles do not activate this path.
type nativeNAT64CallbackModel struct {
	mapped      *nativeNAT46Model
	callerClass policy.NAT64TargetClass
}

func newNativeNAT64CallbackModel(ctx context.Context, baseline policy.Baseline, callback *nativeNAT64CallbackTransport) (*nativeNAT64CallbackModel, error) {
	if ctx == nil || callback == nil || callback.native == nil || callback.native.geometry == nil || callback.proof == nil || callback.native.callbacks != callback {
		return nil, errors.New("firewall: missing original NAT64 callback policy geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := callback.native.geometry.Capture(ctx, callback.native.component, nil, callback.native.mappings); err != nil {
		return nil, err
	}
	data, err := json.Marshal(baseline)
	if err != nil {
		return nil, errors.New("firewall: callback baseline encoding failed")
	}
	owned, err := policy.DecodeBaseline(data)
	if err != nil {
		return nil, err
	}
	transport, err := newNativeNAT64Transport(ctx, owned, callback.native.component)
	if err != nil {
		return nil, err
	}
	if transport.baselineHash != callback.native.baselineHash || transport.prefix != callback.native.prefix ||
		transport.pool != callback.native.pool || transport.name != callback.native.name {
		return nil, errors.New("firewall: NAT64 callback policy changed original baseline")
	}
	expected, err := newNativeNAT64CallbackTransport(ctx, transport)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(expected.proof.legs, callback.proof.legs) {
		return nil, errors.New("firewall: NAT64 callback policy changed retained mappings")
	}
	rules, err := newNativeRuleSet(owned)
	if err != nil {
		return nil, err
	}
	class, err := transport.geometry.TargetClass(ctx, transport.component)
	if err != nil {
		return nil, err
	}
	// A translated alias cannot become a new native IPv4 caller identity.
	class.Excluded = append(class.Excluded, owned.NAT46Pools...)
	for _, component := range owned.NAT64 {
		class.Excluded = append(class.Excluded, *component.SourcePool)
	}
	model := &nativeNAT64CallbackModel{callerClass: class, mapped: &nativeNAT46Model{
		baselineHash: transport.baselineHash, component: transport.component, namespace: transport.name + "_callback",
		prefix: transport.prefix, rules: rules,
	}}
	for _, zone := range owned.Zones {
		if owned.DirectoryManaged(zone.Role) {
			model.mapped.managed = append(model.mapped.managed, zone.Interfaces...)
		}
	}
	for _, leg := range expected.proof.legs {
		if !leg.reply && leg.protocol == "tcp" {
			model.mapped.mappings = append(model.mapped.mappings, leg.mapping)
		}
	}
	if err := model.mapped.projectAliases(ctx); err != nil {
		return nil, err
	}
	return model, ctx.Err()
}

func (model *nativeNAT64CallbackModel) wirePolicy(ctx context.Context, originalRule, mappingIndex int, original nativePacketContext, protocol string, reply, physical bool) (*nativeNAT46Policy, error) {
	if ctx == nil || model == nil || model.mapped == nil || len(model.callerClass.Allowed) == 0 {
		return nil, errors.New("firewall: missing NAT64 callback policy origin")
	}
	program, err := model.mapped.wirePolicy(ctx, originalRule, mappingIndex, original, protocol, reply, physical)
	if err != nil {
		return nil, err
	}
	count := 3 + len(model.callerClass.Excluded) + len(model.callerClass.Allowed)
	for _, rules := range program.chains {
		count += len(rules)
	}
	if count > nativeRuleCapacity {
		return nil, errors.New("firewall: NAT64 callback wire policy exceeds capacity")
	}
	scope, class := program.entry+"_scope", program.entry+"_caller_class"
	program.chains[scope] = program.chains[program.entry]
	program.chains[program.entry] = []nativeScope{nativeVerdict("jump", class), nativeVerdict("goto", scope)}
	field := "saddr"
	if reply {
		field = "daddr"
	}
	for _, prefix := range model.callerClass.Excluded {
		program.chains[class] = append(program.chains[class], nativeJoin(model.callerPrefix(field, prefix), nativeVerdict("drop", "")))
	}
	for _, prefix := range model.callerClass.Allowed {
		program.chains[class] = append(program.chains[class], nativeJoin(model.callerPrefix(field, prefix), nativeVerdict("return", "")))
	}
	program.chains[class] = append(program.chains[class], nativeVerdict("drop", ""))
	return program, ctx.Err()
}

func (model *nativeNAT64CallbackModel) callerPrefix(field string, prefix netip.Prefix) nativeScope {
	embedded := nativeNAT46SourcePrefix(model.mapped.prefix, prefix)
	return nativeMatch("ip6 "+field+" "+embedded.String(), guardPayload("ip6", field), controllerPrefix(embedded))
}
