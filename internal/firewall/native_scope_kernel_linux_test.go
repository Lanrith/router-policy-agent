//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// This qualifies only normalized packet predicates. It is not an owner-access
// program: grants, mandatory source guards and epoch admission remain separate.
func TestKernelNamedNativePredicatesRetainEveryField(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	packetIP(ctx, t, "neighbor", "add", "10.240.0.11", "lladdr", "02:00:00:00:00:10", "dev", "lan10", "nud", "permanent")
	packetIP(ctx, t, "neighbor", "add", "fdca:1a2b::11", "lladdr", "02:00:00:00:00:10", "dev", "lan10", "nud", "permanent")
	packetNft(ctx, t, `table netdev native_scope_endpoints {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table netdev native_scope_endpoints")
	})
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, reply := range []bool{false, true} {
				for _, physical := range []bool{false, true} {
					t.Run(fmt.Sprintf("ipv%d/%s/reply=%t/physical=%t", family, protocol, reply, physical), func(t *testing.T) {
						for index, variation := range []string{"matching", "CIDR", "wildcard", "zero_prefix", "source", "destination", "interface", "port", "protocol", "MAC", "literal_alternatives", "literal_prefixes", "literal_second", "literal_source_gap", "literal_port_gap"} {
							if variation == "MAC" && reply != physical {
								continue // This MAC can be checked only at its appropriate hook.
							}
							t.Run(variation, func(t *testing.T) {
								baseline := nativeScopeBaseline(t)
								rule := &baseline.NetworkModel.Rules[0]
								rule.Protocol, rule.Family = protocol, family
								source, target := netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("10.240.3.10")
								if family == 6 {
									source, target = netip.MustParseAddr("fdca:1a2b::10"), netip.MustParseAddr("fdca:1a2b:3::10")
								}
								input, output, outgoing := peer, device, "lan13"
								etherSource, etherTarget := "02:00:00:00:00:10", "02:00:00:00:01:10"
								sport, dport := uint16(40000), uint16(6053)
								if reply {
									input, output, outgoing = device, peer, "lan10"
									source, target, sport, dport = target, source, dport, sport
									etherSource, etherTarget = "02:00:00:00:00:13", "02:00:00:00:01:13"
								}
								if variation == "CIDR" || variation == "zero_prefix" {
									bits := 24
									if family == 6 {
										bits = 64
									}
									if variation == "zero_prefix" {
										bits = 0
									}
									for _, endpoint := range []*[]netip.Prefix{&rule.From[0].Addresses, &rule.To[0].Addresses} {
										for index, prefix := range *endpoint {
											if prefix.Addr().Is4() == (family == 4) {
												(*endpoint)[index] = netip.PrefixFrom(prefix.Addr(), bits).Masked()
											}
										}
									}
								}
								if variation == "wildcard" {
									rule.From[0].Addresses, rule.To[0].Addresses = nil, nil
								}
								if strings.HasPrefix(variation, "literal_") {
									for _, endpoint := range []*[]netip.Prefix{&rule.From[0].Addresses, &rule.To[0].Addresses} {
										for _, prefix := range slices.Clone(*endpoint) {
											if prefix.Addr().Is4() == (family == 4) {
												*endpoint = append(*endpoint, netip.PrefixFrom(prefix.Addr().Next().Next(), prefix.Bits()))
											}
										}
									}
									if variation == "literal_prefixes" {
										from, to := "10.242.0.0/24", "10.243.0.0/24"
										bits := 24
										if family == 6 {
											from, to, bits = "fdca:1a2b:5::/64", "fdca:1a2b:6::/64", 64
										}
										for _, endpoint := range []*[]netip.Prefix{&rule.From[0].Addresses, &rule.To[0].Addresses} {
											for i, prefix := range *endpoint {
												if prefix.Addr().Is4() == (family == 4) {
													(*endpoint)[i] = netip.PrefixFrom(prefix.Addr(), bits).Masked()
												}
											}
										}
										rule.From[0].Addresses = append(rule.From[0].Addresses, netip.MustParsePrefix(from))
										rule.To[0].Addresses = append(rule.To[0].Addresses, netip.MustParsePrefix(to))
										// Replace the point alternatives with their containing prefix.
										for _, endpoint := range []*[]netip.Prefix{&rule.From[0].Addresses, &rule.To[0].Addresses} {
											seen := map[netip.Prefix]bool{}
											retained := []netip.Prefix{}
											for _, prefix := range *endpoint {
												if !seen[prefix] {
													seen[prefix] = true
													retained = append(retained, prefix)
												}
											}
											*endpoint = retained
										}
									}
									rule.Ports = []uint16{6053, 6055}
									if variation == "literal_source_gap" {
										source = source.Next()
									}
									if variation == "literal_second" {
										source = source.Next().Next()
									}
									if variation == "literal_alternatives" {
										if reply {
											sport = 6055
										} else {
											dport = 6055
										}
									}
									if variation == "literal_port_gap" {
										if reply {
											sport = 6054
										} else {
											dport = 6054
										}
									}
								}
								if variation == "source" {
									source = source.Next()
								}
								if variation == "destination" {
									target = target.Next()
								}
								if variation == "interface" {
									// Keep the IP packet unchanged; change only one root
									// selector so the actual attachment must fail its match.
									if physical == reply {
										rule.From[0].Interface = "lan13"
									} else {
										rule.To[0].Interface = "lan10"
									}
								}
								if variation == "port" {
									if reply {
										sport++
									} else {
										dport++
									}
								}
								isTCP := protocol == "tcp"
								if variation == "protocol" {
									isTCP = !isTCP
								}
								if variation == "MAC" {
									rule.From[0].MAC = "02:00:00:00:00:ee"
								}
								set, err := newNativeRuleSet(baseline)
								if err != nil {
									t.Fatal(err)
								}
								scopes, err := set.scopes(ctx, 0, reply, physical)
								if err != nil || len(scopes) != 1 {
									t.Fatal("single-family scope did not compile", err)
								}
								objectFamily, hook := "inet", "forward"
								binding := ""
								if physical {
									objectFamily, hook, binding = "netdev", "egress", fmt.Sprintf("device %q ", outgoing)
								}
								packetNft(ctx, t, fmt.Sprintf("table %s native_scope_fixture {\n counter reached {}\n counter selected {}\n chain fixture_check {\n type filter hook %s %spriority 0; policy drop;\n meta l4proto { tcp, udp } counter name reached\n %s counter name selected accept\n }\n}\n",
									objectFamily, hook, binding, scopes[0].text))
								t.Cleanup(func() {
									cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
									defer done()
									packetNft(cleanup, t, "delete table "+objectFamily+" native_scope_fixture")
								})
								inspectNativeScope(ctx, t, objectFamily, scopes[0])
								frame := packetFrame(t, packetDatagram{source: source, destination: target,
									sourceMAC: etherSource, destinationMAC: etherTarget, sourcePort: sport, destinationPort: dport,
									isTCP: isTCP, tcpFlags: 2, payload: fmt.Sprintf("native-%d-%s-%t-%t-%d", family, protocol, reply, physical, index)})
								sendPacket(ctx, t, input, frame)
								matched := variation == "matching" || variation == "CIDR" || variation == "wildcard" || variation == "zero_prefix" || variation == "literal_alternatives" || variation == "literal_prefixes" || variation == "literal_second"
								receivePacket(ctx, t, output, frame, matched)
								wanted := uint64(0)
								if matched {
									wanted = 1
								}
								if guardFamilyCounter(ctx, t, objectFamily, "native_scope_fixture", "reached") != 1 ||
									guardFamilyCounter(ctx, t, objectFamily, "native_scope_fixture", "selected") != wanted {
									t.Fatal("predicate did not inspect and retain the exact packet scope")
								}
							})
						}
					})
				}
			}
		}
	}
}

func inspectNativeScope(ctx context.Context, t *testing.T, family string, expected nativeScope) {
	t.Helper()
	data := kernelFixtureCommand(ctx, t, "list", "chain", family, "native_scope_fixture", "fixture_check")
	var decoded struct {
		Objects []struct {
			Rule *struct {
				Expr []any `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	var actual []any
	for _, item := range decoded.Objects {
		if item.Rule != nil {
			actual = item.Rule.Expr
		}
	}
	if len(actual) < 2 {
		t.Fatal("native predicate listing is incomplete")
	}
	raw, err := json.Marshal(expected.expressions)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalFixedGuardJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(actual[:len(actual)-2])
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalFixedGuardJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("native predicate AST differs: actual=%s expected=%s", got, want)
	}
}
