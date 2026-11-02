package firewall

import (
	"context"
	"errors"
)

// Observation checks the fixed retained destination geometry, caller class,
// native IPv6 ownership, logical permission, epoch, lifetime and both mirrors.
// It supplies no source receipt, live runtime origin or positive authorization.
func (model *nativeNAT64CallbackModel) inspectTargetGrants(ctx context.Context, logical guardChanges, inet, netdev *guardTableObservation) (int, error) {
	if ctx == nil || model == nil || model.callback == nil || model.callback.native == nil {
		return 0, errors.New("firewall: missing callback observation dependencies")
	}
	models, err := nativeNAT64CallbackModels([]*nativeNAT64Transport{model.callback.native})
	if err != nil || len(models) != 1 || models[0] != model {
		return 0, errors.New("firewall: callback observation changed original model")
	}
	filtered, err := model.filterLogicalGrants(ctx, logical)
	if err != nil {
		return 0, err
	}
	return model.mapped.inspectTargetGrants(ctx, filtered, inet, netdev)
}
