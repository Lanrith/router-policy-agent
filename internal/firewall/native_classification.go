package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/state"
)

// Native preparation adds only permanent address mirrors and expiring grants.
// It derives them from the already validated logical transaction; no caller can
// supply a separate physical identity, remove history, or extend a grant.
func prepareLayoutGuards(ctx context.Context, source *preparedBatch, history *state.Classification, layout *guardLayout) (*preparedGuardBatch, error) {
	if sources := layout.nat46Sources(); sources != nil && history != nil {
		projected, err := sources.model.translatedClassification(ctx, *history)
		if err != nil {
			return nil, err
		}
		history = &projected
	}
	prepared, err := prepareMappedGuards(ctx, source, history, layout.translationPaths)
	if err != nil || layout.native == nil {
		return prepared, err
	}
	if sources := layout.nat46Sources(); sources != nil {
		prepared, err = prepareNativeNAT46Guards(ctx, prepared, nil, sources.model, time.Time{})
		if err != nil {
			return nil, err
		}
		if transports := layout.native.selectedNAT64Transports(); len(transports) != 0 {
			return attachNativeNAT64Grants(ctx, prepared, nil, transports)
		}
		return prepared, nil
	}
	if transports := layout.native.selectedNAT64Transports(); len(transports) != 0 {
		return prepareNativeNAT64AggregateGuards(ctx, prepared, nil, transports, time.Time{})
	}
	return prepareNativeGuards(ctx, prepared)
}

func prepareNativeGuards(ctx context.Context, source *preparedGuardBatch) (*preparedGuardBatch, error) {
	return prepareNativeGuardsWithSource(ctx, source, nil, "", time.Time{})
}

func prepareNativeGuardsWithSource(ctx context.Context, source *preparedGuardBatch, publication *nativeSourcePublication, baselineHash string, utc time.Time) (*preparedGuardBatch, error) {
	if source == nil || source.native {
		return nil, errors.New("firewall: invalid native guard preparation")
	}
	if err := validatePreparedGuardBatch(ctx, source); err != nil {
		return nil, err
	}
	anchor := time.Time{}
	if publication != nil {
		if source.batch.startedAt.IsZero() || utc.IsZero() || !utc.Equal(source.batch.preparedAt) || !generationHash(baselineHash) {
			return nil, errors.New("firewall: native ID grants require their original timed preparation")
		}
		anchor = time.Now()
	}
	data, err := expandNativeGuardsWithSource(ctx, source.batch.data, publication, baselineHash, utc, anchor)
	if err != nil {
		return nil, err
	}
	prepared := *source
	prepared.batch.data = data
	prepared.native = true
	prepared.sourcePublication, prepared.sourceBaselineHash, prepared.sourceUTC, prepared.sourceAnchor = publication, baselineHash, utc, anchor
	return &prepared, nil
}

func expandNativeGuards(ctx context.Context, source []byte) ([]byte, error) {
	return expandNativeGuardsWithSource(ctx, source, nil, "", time.Time{}, time.Time{})
}

func expandNativeGuardsWithSource(ctx context.Context, source []byte, publication *nativeSourcePublication, baselineHash string, utc, anchor time.Time) ([]byte, error) {
	decoded, err := decodeGuardChanges(source)
	if err != nil {
		return nil, err
	}
	for _, command := range decoded.Commands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family == "inet" && element.Table == ownedTable && (element.Name == classified4Set || element.Name == classified6Set) {
			decoded.Commands = append(decoded.Commands, guardAdd("netdev", element.Name, element.Values))
		}
	}
	projections, err := projectNativeGrants(ctx, decoded)
	if err != nil {
		return nil, err
	}
	decoded.Commands = append(decoded.Commands, projections...)
	idGrants := clearNativeIDGrants()
	if publication != nil {
		idGrants, err = projectNativeIPv4GrantIDs(ctx, decoded, publication, baselineHash, utc, anchor)
		if err != nil {
			return nil, err
		}
	}
	decoded.Commands = append(decoded.Commands, idGrants...)
	data, err := json.Marshal(decoded)
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: native guard encoding or quota failed")
	}
	return data, ctx.Err()
}

func stripNativeGuards(source []byte) ([]byte, error) {
	decoded, err := decodeGuardChanges(source)
	if err != nil {
		return nil, err
	}
	commands := make([]change, 0, len(decoded.Commands))
	refs := append(nativeGrantRefs(), nativeNAT46TargetGrantRefs()...)
	refs = append(refs, nativeNAT64GrantRefs()...)
	for _, command := range decoded.Commands {
		if command.Flush != nil && slices.Contains(refs, command.Flush.Set) {
			continue
		}
		if command.Add != nil {
			element := command.Add.Element
			if slices.Contains(refs, objectReference{Family: element.Family, Table: element.Table, Name: element.Name}) {
				continue
			}
			if element.Family == "netdev" && element.Table == ownedTable && (element.Name == classified4Set || element.Name == classified6Set) {
				continue
			}
		}
		commands = append(commands, command)
	}
	return json.Marshal(guardChanges{Commands: commands})
}

func validateNativeGuardBatch(ctx context.Context, prepared *preparedGuardBatch) error {
	logical, err := stripNativeGuards(prepared.batch.data)
	if err != nil {
		return err
	}
	if err := validateMappedGuardBatch(ctx, logical, prepared.classification, prepared.translationPaths); err != nil {
		return err
	}
	if prepared.sourcePublication == nil {
		if prepared.sourceBaselineHash != "" || !prepared.sourceUTC.IsZero() || !prepared.sourceAnchor.IsZero() {
			return errors.New("firewall: native grant source receipt is incomplete")
		}
	} else if prepared.batch.startedAt.IsZero() || prepared.sourceAnchor.Before(prepared.batch.startedAt) || time.Since(prepared.sourceAnchor) < 0 || !prepared.sourceUTC.Equal(prepared.batch.preparedAt) || !generationHash(prepared.sourceBaselineHash) {
		return errors.New("firewall: native ID grant preparation anchor changed")
	}
	expected, err := expandNativeGuardsWithSource(ctx, logical, prepared.sourcePublication, prepared.sourceBaselineHash, prepared.sourceUTC, prepared.sourceAnchor)
	if err != nil {
		return err
	}
	if prepared.nat46Model != nil {
		expected, err = prepared.nat46Model.expandTargetGuards(ctx, expected, prepared.sourcePublication, prepared.sourceUTC, prepared.sourceAnchor)
		if err != nil {
			return err
		}
		if prepared.sourcePublication != nil && prepared.nat46Model.baselineHash != prepared.sourceBaselineHash {
			return errors.New("firewall: nat46 grant model changed baseline")
		}
	}
	transports, err := preparedNativeNAT64Transports(prepared)
	if err != nil {
		return err
	}
	if len(transports) != 0 {
		expected, err = expandNativeNAT64Grants(ctx, expected, prepared.sourcePublication, transports, prepared.sourceUTC, prepared.sourceAnchor)
		if err != nil {
			return err
		}
		for _, transport := range transports {
			if prepared.sourcePublication != nil && transport.baselineHash != prepared.sourceBaselineHash {
				return errors.New("firewall: NAT64 grant model changed baseline")
			}
		}
	}
	actual, err := canonicalGuardJSON(prepared.batch.data)
	if err != nil {
		return err
	}
	wanted, err := canonicalGuardJSON(expected)
	if err != nil || !bytes.Equal(actual, wanted) {
		return errors.New("firewall: native physical projections differ")
	}
	if err := validateNativeIDGrantDeadlines(ctx, prepared); err != nil {
		return err
	}
	if err := validateNAT46TargetGrantDeadlines(ctx, prepared); err != nil {
		return err
	}
	if err := validateNAT64GrantDeadlines(ctx, prepared); err != nil {
		return err
	}
	return ctx.Err()
}
