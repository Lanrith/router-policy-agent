package firewall

import (
	"errors"
	"slices"
)

func (layout *guardLayout) nat64CallbackModels() ([]*nativeNAT64CallbackModel, error) {
	if layout == nil {
		return nil, nil
	}
	var transports []*nativeNAT64Transport
	if layout.native != nil {
		transports = layout.native.selectedNAT64Transports()
	}
	models, err := nativeNAT64CallbackModels(transports)
	if err != nil {
		return nil, err
	}
	if layout.inspectionSchemas != nil && !slices.Equal(models, layout.callbackModels) {
		return nil, errors.New("firewall: callback selection differs from frozen layout")
	}
	return models, nil
}

// Only a construction-selected original model can name callback collections.
// The returned pointers are compile-time identity, never current permission.
// Preserve nil for ordinary layouts, including tuple-only callback fixtures.
func nativeNAT64CallbackModels(transports []*nativeNAT64Transport) ([]*nativeNAT64CallbackModel, error) {
	var models []*nativeNAT64CallbackModel
	seen := map[string]bool{}
	for index, transport := range transports {
		if transport == nil {
			return nil, errors.New("firewall: missing selected callback transport")
		}
		callback := transport.callbacks
		if callback == nil || callback.grants == nil {
			continue
		}
		model := callback.grants
		if len(transports) > 4 || callback.native != transport || model.callback != callback || model.mapped == nil ||
			!generationHash(transport.baselineHash) || model.mapped.baselineHash != transport.baselineHash ||
			model.mapped.namespace != transport.name+"_callback" || model.mapped.prefix != transport.prefix ||
			model.mapped.translator() != transport.component || seen[model.mapped.namespace] {
			return nil, errors.New("firewall: selected callback grant model differs from original geometry")
		}
		seen[model.mapped.namespace] = true
		if models == nil {
			models = make([]*nativeNAT64CallbackModel, len(transports))
		}
		models[index] = model
	}
	return models, nil
}

func nativeNAT64CallbackGrantRefs(models []*nativeNAT64CallbackModel) []objectReference {
	refs := []objectReference{}
	for _, model := range models {
		if model != nil {
			refs = append(refs, nativeMappedTargetGrantRefs(model.mapped.policyNamespace())...)
		}
	}
	return refs
}

func decodePreparedGuardChanges(prepared *preparedGuardBatch) (guardChanges, error) {
	if _, err := preparedNativeNAT64Transports(prepared); err != nil {
		return guardChanges{}, err
	}
	return decodeGuardChangesWithExtra(prepared.batch.data, 2*len(nativeNAT64CallbackGrantRefs(prepared.nat64Callbacks)))
}
