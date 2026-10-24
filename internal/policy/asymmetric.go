package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// AsymmetricReply is a narrowly generated exception for a return path which
// cannot be inferred from conntrack. It is not a general owner access rule.
type AsymmetricReply struct {
	Mode                 string         `json:"mode"`
	SourceInterface      string         `json:"source_interface"`
	SourceAddresses      []netip.Prefix `json:"source_addresses"`
	DestinationInterface string         `json:"destination_interface"`
	DestinationAddresses []netip.Prefix `json:"destination_addresses"`
}

func decodeAsymmetricReplies(raw []json.RawMessage) error {
	for _, reply := range raw {
		if err := strictjson.Object(reply, []string{"mode", "source_interface", "source_addresses", "destination_interface", "destination_addresses"}, nil, 2<<20); err != nil {
			return err
		}
	}
	return nil
}

func validateAsymmetricReplies(b Baseline, interfaces map[string]bool) error {
	replies := b.NetworkModel.AsymmetricReplies
	if len(replies) > 64 {
		return errors.New("policy: asymmetric reply capacity exceeded")
	}
	seen := map[string]bool{}
	for _, reply := range replies {
		if !slices.Contains([]string{"tcp_dsr", "icmp_echo_reply"}, reply.Mode) ||
			!safeInterface(reply.SourceInterface) || !interfaces[reply.SourceInterface] ||
			!safeInterface(reply.DestinationInterface) || !interfaces[reply.DestinationInterface] ||
			len(reply.SourceAddresses) == 0 || len(reply.SourceAddresses) > 256 ||
			len(reply.DestinationAddresses) == 0 || len(reply.DestinationAddresses) > 256 {
			return errors.New("policy: invalid asymmetric reply geometry")
		}
		for _, entry := range []struct {
			iface    string
			prefixes []netip.Prefix
		}{{reply.SourceInterface, reply.SourceAddresses}, {reply.DestinationInterface, reply.DestinationAddresses}} {
			zone := false
			for _, candidate := range b.Zones {
				if slices.Contains(candidate.Interfaces, entry.iface) {
					zone = true
					for _, prefix := range entry.prefixes {
						if !prefix.IsValid() || prefix != prefix.Masked() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
							return errors.New("policy: asymmetric reply escapes its IPv6 attachment")
						}
						attached := slices.ContainsFunc(candidate.Networks, func(network netip.Prefix) bool {
							return network.Addr().Is6() && network.Bits() <= prefix.Bits() && network.Contains(prefix.Addr())
						})
						if !attached {
							return errors.New("policy: asymmetric reply escapes its IPv6 attachment")
						}
						for _, block := range b.ProtectedNetworks {
							// The native raw floor is evaluated before an asymmetric
							// exception, so a broad attached source prefix may include
							// isolated router addresses without admitting them. Reject
							// an exception wholly inside P01: it has no safe packet to
							// admit and usually indicates a mistaken control-plane rule.
							if block.ProtectionID == "P01" && prefixContainedBy(prefix, block.Networks) {
								return errors.New("policy: asymmetric reply is contained by router or management protection")
							}
						}
					}
				}
			}
			if !zone {
				return errors.New("policy: asymmetric reply requires ordinary attachments")
			}
		}
		data, err := json.Marshal(reply)
		if err != nil || seen[string(data)] {
			return errors.New("policy: duplicate asymmetric reply")
		}
		seen[string(data)] = true
	}
	return nil
}

func prefixContainedBy(prefix netip.Prefix, others []netip.Prefix) bool {
	for _, other := range others {
		if other.Bits() <= prefix.Bits() && other.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
