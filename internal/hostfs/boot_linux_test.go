package hostfs

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestKernelBootIDIsAnIndependentReadOnlyProcfsObservation(t *testing.T) {
	t.Parallel()
	first, err := KernelBootID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(first)
	if err != nil || len(decoded) != 16 {
		t.Fatal("kernel boot observation is not canonical", first, err)
	}
	if second, err := KernelBootID(t.Context()); err != nil || first != second {
		t.Fatal("kernel boot observation is unstable", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if boot, err := KernelBootID(ctx); !errors.Is(err, context.Canceled) || boot != "" {
		t.Fatal("canceled boot observation supplied a namespace", boot, err)
	}
	//nolint:staticcheck // Deliberately invalid API input.
	if boot, err := KernelBootID(nil); err == nil || boot != "" {
		t.Fatal("missing context supplied a boot namespace")
	}
	file, err := os.CreateTemp(t.TempDir(), "forged-boot-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := file.WriteString("12345678-1234-1234-1234-123456789abc\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if boot, err := readKernelBootID(t.Context(), file); err == nil || boot != "" {
		t.Fatal("ordinary file supplied a kernel boot namespace")
	}
}

func TestKernelBootIDRejectsNoncanonicalNamespaces(t *testing.T) {
	t.Parallel()
	valid := "12345678-1234-1234-1234-123456789abc\n"
	if boot, err := parseKernelBootID([]byte(valid)); err != nil || boot != "12345678123412341234123456789abc" {
		t.Fatal("canonical boot rejected", boot, err)
	}
	for _, raw := range []string{"", strings.TrimSpace(valid), valid + "\n", strings.ToUpper(valid),
		"00000000-0000-0000-0000-000000000000\n", strings.Replace(valid, "-", ":", 1),
		strings.Replace(valid, "a", "g", 1), valid[:36] + "\x00"} {
		if boot, err := parseKernelBootID([]byte(raw)); err == nil || boot != "" {
			t.Fatalf("noncanonical boot %q supplied %q", raw, boot)
		}
	}
}
