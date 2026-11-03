package maintenance_test

import (
	"regexp"
	"strconv"
	"testing"
)

// The older reviewed source stops on an inventory-only OpenPGP advisory before
// checking imports. Keep that source out of complete as well as partial rollbacks.
func TestMaintenanceSourceSupportsAdvisoryApplicability(t *testing.T) {
	t.Parallel()
	_, source := reviewedMaintenanceSource(t)
	if !supportsAdvisoryApplicability(source.Version) {
		t.Fatalf("maintenance source %s predates the verified v0.1.18 applicability fix for GO-2026-5932", source.Version)
	}
}

func TestAdvisoryMaintenanceVersionFloor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "deployed legacy source", version: "v0.1.12"},
		{name: "lexical comparison trap", version: "v0.1.9"},
		{name: "previous release", version: "v0.1.17"},
		{name: "verified fix", version: "v0.1.18", want: true},
		{name: "later patch", version: "v0.1.19", want: true},
		{name: "later minor", version: "v0.2.0", want: true},
		{name: "later major", version: "v1.0.0", want: true},
		{name: "prerelease", version: "v0.1.18-rc.1"},
		{name: "missing version prefix", version: "0.1.18"},
		{name: "malformed version", version: "v0.1"},
		{name: "overflow", version: "v0.1.18446744073709551616"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := supportsAdvisoryApplicability(tt.version); got != tt.want {
				t.Errorf("supportsAdvisoryApplicability(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func supportsAdvisoryApplicability(version string) bool {
	parts := regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).FindStringSubmatch(version)
	if parts == nil {
		return false
	}
	var actual [3]uint64
	for i := range actual {
		number, err := strconv.ParseUint(parts[i+1], 10, 64)
		if err != nil {
			return false
		}
		actual[i] = number
	}
	for i, minimum := range [3]uint64{0, 1, 18} {
		if actual[i] != minimum {
			return actual[i] > minimum
		}
	}
	return true
}
