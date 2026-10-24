package firewall

import (
	"fmt"
	"strings"
	"testing"
)

func TestOwnerPrioritySlotDoesNotOverlapQoSOrRuleIdentity(t *testing.T) {
	t.Parallel()
	if ownerPriorityMask&uint64(ownershipRuleMask) != 0 || ownerPriorityMask&0x00ff0000 != 0 || ownerPriorityMask&0xff000000 != 0 {
		t.Fatal("priority slot overlaps an admitted identity or QoS field")
	}
	for _, original := range []uint64{0, 0xb1000000, 0xb1370025, 0xaaff03ff} {
		for priority := uint64(0); priority <= 7; priority++ {
			t.Run(fmt.Sprintf("mark=%x/priority=%d", original, priority), func(t *testing.T) {
				t.Parallel()
				saved := original&ownerPriorityKeep | priority<<10
				if saved&ownerPriorityMask>>10 != priority || saved&ownerPriorityKeep != original&ownerPriorityKeep {
					t.Fatal("priority preservation changed another field")
				}
			})
		}
	}
}

func TestOwnerPriorityHelpersAreFixedAndRejectTruncation(t *testing.T) {
	t.Parallel()
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "save", true: "restore"}[restore], func(t *testing.T) {
			t.Parallel()
			rules := ownerPriorityRules(restore)
			if len(rules) != 11 || rules[len(rules)-2] != "drop" || strings.Contains(strings.Join(rules, "\n"), "ct ") {
				t.Fatal("priority helper has an unbounded or permissive fallback")
			}
			for _, line := range rules[1 : len(rules)-2] {
				if !restore && strings.Contains(line, "accept") || restore && strings.Contains(line, "return") {
					t.Fatal("priority helper changed its control-flow contract")
				}
			}
		})
	}
}
