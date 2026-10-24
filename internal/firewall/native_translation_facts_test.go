package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestTranslationFactsReserveOnlyAuthorizationBits(t *testing.T) {
	t.Parallel()
	bits := nativeFactBits()
	if len(bits) != 53 {
		t.Fatal("authorization snapshot width changed", len(bits))
	}
	seen := map[uint]bool{}
	for _, bit := range bits {
		if seen[bit.label] || bit.label < 32 || bit.label > 95 || bit.label == nativeFactsValidBit {
			t.Fatal("facts reused an allocation, validity or other component bit")
		}
		seen[bit.label] = true
		if bit.field == "mark" && bit.mask&0x00ff1c00 != 0 {
			t.Fatal("packet QoS or saved priority became sticky authorization")
		}
	}
	if seen[nativeFactsValidBit] || seen[31] {
		t.Fatal("facts consumed an independently owned label field")
	}
}

func TestTranslationFactsCannotInstallPermissionOrRewriteConnectionEpoch(t *testing.T) {
	t.Parallel()
	chains, err := nativeTranslationFacts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) == 0 {
		t.Fatal("missing fixed fact program")
	}
	for name, rules := range chains {
		for _, rule := range rules {
			if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") ||
				strings.Contains(rule.text, "ct mark set") || strings.Contains(rule.text, "update @") {
				t.Fatal("fact transport acquired publication or forwarding authority", name)
			}
			for _, expression := range rule.expressions {
				raw, err := json.Marshal(expression)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), `"accept"`) || strings.Contains(string(raw), `"add"`) ||
					strings.Contains(string(raw), `"map"`) {
					t.Fatal("fact expression acquired mutation authority", name)
				}
			}
		}
	}
	capture := strings.Join(nativeRulesText(chains["native_translation_facts_capture_current"]), "\n")
	if !strings.Contains(capture, "ct status confirmed drop") ||
		!strings.Contains(capture, "goto native_translation_facts_compare") {
		t.Fatal("a confirmed connection can acquire or replace authorization facts")
	}
	restore := strings.Join(nativeRulesText(chains["native_translation_facts_restore"]), "\n")
	if !strings.Contains(restore, "ct direction reply") || !strings.Contains(restore, "ct state established") ||
		!strings.Contains(restore, "ct label & 127 == 127") {
		t.Fatal("reply facts can be manufactured by an unsolicited original packet")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeTranslationFacts(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled fact construction continued", err)
	}
}
