package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
	"github.com/lanrith/router-policy-agent/internal/tunpolicy"
)

type tunProfile struct {
	SchemaVersion int             `json:"schema_version"`
	Backend       string          `json:"backend"`
	ProgramSHA256 string          `json:"program_sha256"`
	Baseline      json.RawMessage `json:"baseline"`
}

// BuildTUNImageProfile binds the already compiled immutable TUN program to the
// delegation ceiling. Runtime receives strict JSON and set schemas, never YAML
// or an access-rule compiler input to regenerate the installed packet program.
func BuildTUNImageProfile(ctx context.Context, baseline, listing []byte, physicalGuards ...[]byte) (ImageProfileArtifacts, error) {
	if ctx == nil {
		return ImageProfileArtifacts{}, errors.New("firewall: missing build context")
	}
	if _, err := policy.DecodeBaseline(baseline); err != nil {
		return ImageProfileArtifacts{}, err
	}
	digest, err := tunpolicy.ProgramDigest(listing)
	if err != nil {
		return ImageProfileArtifacts{}, err
	}
	profile, err := json.Marshal(tunProfile{SchemaVersion: 1, Backend: "tun", ProgramSHA256: digest, Baseline: baseline})
	if err != nil {
		return ImageProfileArtifacts{}, err
	}
	guards := []byte("# TUN guards are compiled into the image nftables program.\n")
	if len(physicalGuards) > 1 {
		return ImageProfileArtifacts{}, errors.New("firewall: expected one physical guard program")
	}
	if len(physicalGuards) == 1 {
		if len(physicalGuards[0]) == 0 || len(physicalGuards[0]) > 2<<20 {
			return ImageProfileArtifacts{}, errors.New("firewall: invalid physical guard program size")
		}
		guards = physicalGuards[0]
	}
	profileSum, guardSum := sha256.Sum256(profile), sha256.Sum256(guards)
	metadata, err := json.Marshal(map[string]any{"schema_version": 1, "profile_sha256": hex.EncodeToString(profileSum[:]),
		"floor_sha256": digest, "guards_sha256": hex.EncodeToString(guardSum[:])})
	if err != nil {
		return ImageProfileArtifacts{}, err
	}
	return ImageProfileArtifacts{Profile: append(profile, '\n'), Guards: guards, Metadata: metadata}, ctx.Err()
}

func decodeTUNProfile(data []byte, expected string) (tunProfile, policy.Baseline, error) {
	failure := func(err error) (tunProfile, policy.Baseline, error) { return tunProfile{}, policy.Baseline{}, err }
	sum := sha256.Sum256(data)
	if !generationHash(expected) || hex.EncodeToString(sum[:]) != expected {
		return failure(errors.New("firewall: TUN profile pin differs"))
	}
	if err := strictjson.Object(data, []string{"schema_version", "backend", "program_sha256", "baseline"}, nil, maximumRouterProfile); err != nil {
		return failure(err)
	}
	var profile tunProfile
	if err := strictjson.Decode(data, &profile, maximumRouterProfile); err != nil {
		return failure(err)
	}
	if profile.SchemaVersion != 1 || profile.Backend != "tun" || !generationHash(profile.ProgramSHA256) {
		return failure(errors.New("firewall: invalid TUN profile"))
	}
	baseline, err := policy.DecodeBaseline(profile.Baseline)
	if err != nil {
		return failure(err)
	}
	if baseline.NetworkModel == nil {
		return failure(errors.New("firewall: TUN profile requires named networks"))
	}
	return profile, baseline, nil
}
