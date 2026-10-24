package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
)

func (layout *guardLayout) nat46Sources() *nativeNAT46StaticSources {
	if layout == nil || layout.native == nil {
		return nil
	}
	return layout.native.nat46Sources
}

// These collections are selected only by an explicit translated layout. They
// supply no hooks or packet permissions. The ordinary native constructor still
// rejects translation, pending the complete floor and translator integration.
func (layout *guardLayout) nat46PublicationDefinitions(ctx context.Context, family string) ([]string, error) {
	sources := layout.nat46Sources()
	var transports []*nativeNAT64Transport
	if layout != nil && layout.native != nil {
		transports = layout.native.selectedNAT64Transports()
	}
	if sources == nil {
		if len(transports) != 0 {
			definitions := nativeNAT64GrantDefinitions(family)
			if family == "inet" {
				for _, transport := range transports {
					definitions = append(definitions, transport.definitions()...)
				}
			}
			return definitions, ctx.Err()
		}
		return nil, nil
	}
	definitions, err := sources.definitions(ctx, family)
	if err != nil {
		return nil, err
	}
	definitions = append(definitions, nat46StaticSourceLiveDefinition())
	if family == "inet" {
		definitions = append(definitions, nat46StaticSourceDefinition())
		if layout.native.nat46Transport != nil {
			definitions = append(definitions, layout.native.nat46Transport.definitions()...)
		}
		for _, transport := range transports {
			definitions = append(definitions, transport.definitions()...)
		}
	}
	definitions = append(definitions, nativeNAT46TargetGrantDefinitions(family)...)
	if len(transports) != 0 {
		definitions = append(definitions, nativeNAT64GrantDefinitions(family)...)
	}
	return definitions, ctx.Err()
}

func (layout *guardLayout) nat46PublicationSchema(ctx context.Context, schema *guardTableSchema, family string) error {
	sources := layout.nat46Sources()
	var transports []*nativeNAT64Transport
	if layout != nil && layout.native != nil {
		transports = layout.native.selectedNAT64Transports()
	}
	if sources == nil {
		if len(transports) != 0 {
			nativeNAT64GrantSchema(schema, family)
			if family == "inet" {
				for _, selected := range transports {
					transport := selected.schema()
					for name, header := range transport.sets {
						schema.sets[name] = header
					}
					for name, header := range transport.maps {
						schema.maps[name] = header
					}
				}
			}
		}
		return nil
	}
	geometry, _, err := sources.staticInventory(ctx, family)
	if err != nil {
		return err
	}
	for name, header := range geometry.sets {
		schema.sets[name] = header
	}
	for name, header := range geometry.maps {
		schema.maps[name] = header
	}
	nat46StaticSourceSchema(schema, family)
	nativeNAT46TargetGrantSchema(schema, family)
	if family == "inet" && layout.native.nat46Transport != nil {
		transport := layout.native.nat46Transport.schema()
		for name, header := range transport.sets {
			schema.sets[name] = header
		}
		for name, header := range transport.maps {
			schema.maps[name] = header
		}
	}
	if family == "inet" {
		for _, selected := range transports {
			transport := selected.schema()
			for name, header := range transport.sets {
				schema.sets[name] = header
			}
			for name, header := range transport.maps {
				schema.maps[name] = header
			}
		}
	}
	if len(transports) != 0 {
		nativeNAT64GrantSchema(schema, family)
	}
	return ctx.Err()
}

// An observed configuration epoch is used only for rejecting changed channel
// rows. It never supplies the OwnerConfiguration proof needed for publication.
func (sources *nativeNAT46StaticSources) inspectConfigurationChannel(ctx context.Context, inet *guardTableObservation) error {
	if ctx == nil || sources == nil || inet == nil {
		return errors.New("firewall: missing nat46 configuration observation")
	}
	if err := inspectConfigurationEpoch(ctx, inet); err != nil {
		return err
	}
	geometry, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	expected := []json.RawMessage{}
	values := inet.sets[configurationEpochSet].Elements
	if len(values) != 0 {
		var base uint32
		if err := json.Unmarshal(values[0], &base); err != nil {
			return err
		}
		lows := []uint32{}
		for _, source := range geometry.Sources {
			lows = append(lows, source.ID&ownershipRuleMask)
		}
		slices.Sort(lows)
		for _, low := range slices.Compact(lows) {
			if err := ctx.Err(); err != nil {
				return err
			}
			row, err := json.Marshal([]any{map[string]any{"concat": []any{base, nativeLowClassID(low)}}, epochClassID(base | low)})
			if err != nil {
				return err
			}
			expected = append(expected, row)
		}
	}
	channel, present := inet.sets[nativeNAT46StaticChannel]
	if !present {
		return errors.New("firewall: missing fixed nat46 configuration channel")
	}
	return sameGuardElements(ctx, channel.Elements, expected)
}

func (layout *guardLayout) inspectNAT46Publications(ctx context.Context, inet, netdev *guardTableObservation) error {
	sources := layout.nat46Sources()
	if sources == nil {
		return nil
	}
	for _, item := range []struct {
		family      string
		observation *guardTableObservation
	}{{"inet", inet}, {"netdev", netdev}} {
		if err := sources.inspectStaticIdentities(ctx, item.family, item.observation); err != nil {
			return err
		}
	}
	if err := sources.inspectConfigurationChannel(ctx, inet); err != nil {
		return err
	}
	return sources.inspectSourceEpoch(ctx, inet, netdev)
}
