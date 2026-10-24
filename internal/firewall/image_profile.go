package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// ImageProfileArtifacts are immutable build outputs. They contain only the
// normalized policy baseline, reviewed nftables contract, and generated guard
// program; the source router configuration is neither accepted nor retained.
type ImageProfileArtifacts struct {
	Profile  []byte
	Guards   []byte
	Metadata []byte
}

type imageProfileMetadata struct {
	SchemaVersion int    `json:"schema_version"`
	ProfileSHA256 string `json:"profile_sha256"`
	FloorSHA256   string `json:"floor_sha256"`
	GuardsSHA256  string `json:"guards_sha256"`
}

type normalizedReviewedObject struct {
	key  string
	data json.RawMessage
}

// BuildImageProfile converts strict JSON build inputs into the only policy
// artifacts needed by the deployed helper. The listing must be captured from
// the completed protected floor before any helper-owned guard table exists.
func BuildImageProfile(ctx context.Context, baselineData, listingData []byte) (ImageProfileArtifacts, error) {
	if ctx == nil {
		return ImageProfileArtifacts{}, errors.New("firewall: missing image profile context")
	}
	if err := ctx.Err(); err != nil {
		return ImageProfileArtifacts{}, err
	}
	baseline, err := policy.DecodeBaseline(baselineData)
	if err != nil {
		return ImageProfileArtifacts{}, fmt.Errorf("firewall: invalid image baseline: %w", err)
	}
	canonicalBaseline, err := json.Marshal(baseline)
	if err != nil {
		return ImageProfileArtifacts{}, errors.New("firewall: image baseline encoding failed")
	}
	reviewed, floorHash, err := buildReviewedRuleset(ctx, listingData)
	if err != nil {
		return ImageProfileArtifacts{}, err
	}
	profile, err := json.Marshal(profileEnvelope{
		SchemaVersion: 1, Baseline: canonicalBaseline, ReviewedRuleset: reviewed,
	})
	if err != nil {
		return ImageProfileArtifacts{}, errors.New("firewall: image profile encoding failed")
	}
	profileHash := sha256Hex(profile)
	// Decode the final bytes through the same path used at runtime. This also
	// proves that the normalized baseline selects a complete guard layout.
	decoded, err := decodePinnedProfile(ctx, profile, profileHash)
	if err != nil {
		return ImageProfileArtifacts{}, fmt.Errorf("firewall: generated image profile invalid: %w", err)
	}
	if decoded.ruleset.digest != floorHash {
		return ImageProfileArtifacts{}, errors.New("firewall: generated floor identity differs")
	}
	guards, err := decoded.layout.program(ctx)
	if err != nil {
		return ImageProfileArtifacts{}, fmt.Errorf("firewall: image guard generation failed: %w", err)
	}
	if len(guards) == 0 || len(guards) > maximumBatch {
		return ImageProfileArtifacts{}, errors.New("firewall: image guard artifact size invalid")
	}
	metadata, err := json.Marshal(imageProfileMetadata{
		SchemaVersion: 1,
		ProfileSHA256: profileHash,
		FloorSHA256:   floorHash,
		GuardsSHA256:  sha256Hex(guards),
	})
	if err != nil {
		return ImageProfileArtifacts{}, errors.New("firewall: image profile metadata encoding failed")
	}
	return ImageProfileArtifacts{
		Profile:  append(profile, '\n'),
		Guards:   guards,
		Metadata: append(metadata, '\n'),
	}, nil
}

func buildReviewedRuleset(ctx context.Context, listingData []byte) ([]byte, string, error) {
	objects, err := decodeRulesetListing(ctx, listingData)
	if err != nil {
		return nil, "", err
	}
	if len(objects) < 2 || len(objects)-1 > maximumRulesetObjects {
		return nil, "", errors.New("firewall: image ruleset inventory size invalid")
	}
	if err := verifyListingMetadata(objects[0]); err != nil {
		return nil, "", err
	}
	normalized := make([]normalizedReviewedObject, 0, len(objects)-1)
	ruleSequence := map[string]int{}
	for _, raw := range objects[1:] {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		_, helperOwned, err := splitOwnedRulesetObject(raw)
		if err != nil {
			return nil, "", err
		}
		if helperOwned {
			return nil, "", errors.New("firewall: image listing already contains helper-owned objects")
		}
		object, err := decodeRulesetObject(raw)
		if err != nil {
			return nil, "", err
		}
		if err := object.normalize(true); err != nil {
			return nil, "", err
		}
		delete(object.fields, "handle")
		fields, err := json.Marshal(object.fields)
		if err != nil {
			return nil, "", errors.New("firewall: normalized image object encoding failed")
		}
		wrapped, err := json.Marshal(map[string]json.RawMessage{object.kind: fields})
		if err != nil {
			return nil, "", errors.New("firewall: reviewed image object encoding failed")
		}
		wrapped, err = canonicalGuardJSON(wrapped)
		if err != nil {
			return nil, "", err
		}
		key := reviewedObjectKey(object, ruleSequence)
		normalized = append(normalized, normalizedReviewedObject{key: key, data: wrapped})
	}
	slices.SortFunc(normalized, func(left, right normalizedReviewedObject) int {
		if left.key < right.key {
			return -1
		}
		if left.key > right.key {
			return 1
		}
		return 0
	})
	artifactObjects := make([]json.RawMessage, len(normalized))
	for index, object := range normalized {
		if index > 0 && normalized[index-1].key == object.key {
			return nil, "", errors.New("firewall: duplicate normalized image object")
		}
		artifactObjects[index] = object.data
	}
	reviewed, err := json.Marshal(struct {
		SchemaVersion int               `json:"schema_version"`
		Objects       []json.RawMessage `json:"objects"`
	}{SchemaVersion: 1, Objects: artifactObjects})
	if err != nil {
		return nil, "", errors.New("firewall: reviewed image ruleset encoding failed")
	}
	contract, err := decodeReviewedRuleset(ctx, reviewed)
	if err != nil {
		return nil, "", fmt.Errorf("firewall: generated reviewed ruleset invalid: %w", err)
	}
	return reviewed, contract.digest, nil
}

func reviewedObjectKey(object rulesetObject, ruleSequence map[string]int) string {
	ranks := map[string]string{
		"table": "0", "chain": "1", "set": "2", "map": "3", "counter": "4", "rule": "5",
	}
	base := ranks[object.kind] + "/" + object.family + "/" + object.table + "/" + object.name
	if object.kind != "rule" {
		return base
	}
	sequence := ruleSequence[base]
	ruleSequence[base] = sequence + 1
	return fmt.Sprintf("%s/%08d", base, sequence)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
