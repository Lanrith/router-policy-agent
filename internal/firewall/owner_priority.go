package firewall

const (
	ownerPriorityMask = uint64(7 << 10)
	ownerPriorityKeep = uint64(0xffffffff) ^ ownerPriorityMask
)

// ownerPriorityRules preserves the standard skb priorities 0..7 in packet-mark
// bits reserved outside the QoS byte and original rule index. The owner path
// must validate its tag and scope before entering either chain. Saving rejects
// other priorities, rather than silently truncating a class identifier. Restore
// runs only after the physical epoch and actual packet scope have matched.
// Neither helper is an owner-access decision or a runtime mutation API.
func ownerPriorityRules(restore bool) []string {
	name := "save_owner_priority"
	if restore {
		name = "restore_owner_priority"
	}
	rules := []string{"chain " + name + " {"}
	rules = append(rules, nativeRulesText(nativePriorityScopes(restore))...)
	return append(rules, "}")
}
