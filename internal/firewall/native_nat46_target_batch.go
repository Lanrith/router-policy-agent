package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"
)

// This component owns the model and receipt needed to reconstruct every mixed
// grant. It does not activate a layout or install its required collections.
// Runtime use still requires complete writer, floor and image admission.
func prepareNativeNAT46Guards(ctx context.Context, source *preparedGuardBatch, publication *nativeSourcePublication, model *nativeNAT46Model, utc time.Time) (*preparedGuardBatch, error) {
	if ctx == nil || model == nil || !generationHash(model.baselineHash) {
		return nil, errors.New("firewall: missing nat46 guard model")
	}
	hash := ""
	if publication != nil {
		hash = model.baselineHash
	} else if !utc.IsZero() {
		return nil, errors.New("firewall: nat46 seal cannot carry an authorization clock")
	}
	prepared, err := prepareNativeGuardsWithSource(ctx, source, publication, hash, utc)
	if err != nil {
		return nil, err
	}
	data, err := model.expandTargetGuards(ctx, prepared.batch.data, publication, prepared.sourceUTC, prepared.sourceAnchor)
	if err != nil {
		return nil, err
	}
	prepared.batch.data = data
	prepared.nat46Model = model
	return prepared, nil
}

func (model *nativeNAT46Model) expandTargetGuards(ctx context.Context, data []byte, publication *nativeSourcePublication, utc, anchor time.Time) ([]byte, error) {
	if ctx == nil || model == nil || !generationHash(model.baselineHash) {
		return nil, errors.New("firewall: missing nat46 target guard geometry")
	}
	changes, err := decodeGuardChanges(data)
	if err != nil {
		return nil, err
	}
	extra := []change{}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		extra = append(extra, change{Flush: &setChange{Set: ref}})
	}
	if publication != nil {
		extra, err = model.projectTargetGrants(ctx, changes, publication, utc, anchor)
		if err != nil {
			return nil, err
		}
	}
	changes.Commands = append(changes.Commands, extra...)
	encoded, err := json.Marshal(changes)
	if err != nil || len(encoded) > maximumBatch {
		return nil, errors.New("firewall: nat46 target guard transaction exceeds capacity")
	}
	return encoded, ctx.Err()
}

func validateNAT46TargetGrantDeadlines(ctx context.Context, prepared *preparedGuardBatch) error {
	if prepared.nat46Model == nil || prepared.sourcePublication == nil {
		return ctx.Err()
	}
	model, publication := prepared.nat46Model, prepared.sourcePublication
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	indexes := map[netip.Addr]int{}
	for index, address := range snapshot.Addresses {
		if address.Address.Is6() {
			indexes[address.Address] = index
		}
	}
	mappings := map[netip.Addr]nativeNAT46Mapping{}
	for _, mapping := range model.mappings {
		mappings[mapping.alias] = mapping
	}
	changes, err := decodeGuardChanges(prepared.batch.data)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, command := range changes.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if !slices.Contains(nativeNAT46TargetGrantRefs(), objectReference{Family: element.Family, Table: element.Table, Name: element.Name}) {
			continue
		}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return err
			}
			var lease struct {
				Value struct {
					Fields []json.RawMessage `json:"concat"`
				} `json:"val"`
				Timeout int `json:"timeout"`
			}
			if decodeNested(raw, "elem", &lease, []string{"val", "timeout"}) != nil || len(lease.Value.Fields) != 4 {
				return errors.New("firewall: invalid prepared nat46 target grant")
			}
			var alias string
			if json.Unmarshal(lease.Value.Fields[1], &alias) != nil {
				return errors.New("firewall: malformed prepared nat46 alias")
			}
			address, err := netip.ParseAddr(alias)
			if err != nil {
				return err
			}
			mapping, found := mappings[address]
			if !found {
				return errors.New("firewall: prepared nat46 grant lost mapping")
			}
			index, found := indexes[mapping.target]
			if !found {
				return errors.New("firewall: prepared nat46 grant lost original ownership")
			}
			remaining, err := publication.remaining(ctx, index, now)
			if err != nil {
				return err
			}
			proofRemaining, err := publication.evidence.Remaining(index, prepared.sourceUTC)
			if err != nil {
				return err
			}
			if lease.Timeout < 1 || time.Duration(lease.Timeout)*time.Second+commandBudget > min(remaining, proofRemaining) {
				return errors.New("firewall: nat46 target grant escaped original source deadline")
			}
		}
	}
	return ctx.Err()
}
