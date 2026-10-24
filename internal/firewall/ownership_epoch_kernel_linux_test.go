//go:build integration && kernel && linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestKernelNamedOwnershipEpochRejectsOldConnections(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	baseline := namedOwnershipBaseline(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	p, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	install := func(t *testing.T, epoch uint32) {
		t.Helper()
		now := time.Now().UTC()
		proof, err := ownershipProofFixture(t, baseline, now, 90*time.Second).InEpoch(ctx, epoch)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := renderer.prepareOwnership(ctx, proof, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateOwnershipPreparation(ctx, prepared, now); err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, prepared.batch.data)
		if _, err := p.inspectGuards(ctx, layout); err != nil {
			listing, inspectionErr := p.execute(ctx, inspectOwned, nil)
			observation, parseErr := layout.inspectTable(ctx, "inet", listing)
			t.Logf("synthetic epoch inspection: read=%v, parse=%v", inspectionErr, parseErr)
			if parseErr == nil {
				t.Logf("epoch mirrors=%v", inspectOwnershipEpoch(ctx, observation))
			}
			t.Fatal("epoch map/set schema or mirrors rejected", err)
		}
	}
	installConfiguration := func(t *testing.T, epoch uint32) {
		t.Helper()
		proof, err := renderer.compiler.CompileOwnerConfiguration(ctx, epoch)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := renderer.prepareConfiguration(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.acquire(ctx); err != nil {
			t.Fatal(err)
		}
		_, err = p.run(ctx, commandInput{op: applyConfiguration, configuration: prepared})
		p.release()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.inspectGuards(ctx, layout); err != nil {
			t.Fatal("configuration mirror inspection failed", err)
		}
	}
	packetIP(ctx, t, "link", "set", "lo", "up")
	for _, family := range []struct {
		network, address string
		epoch            uint32
		configuration    bool
	}{{"udp4", "127.0.0.1", 7, false}, {"udp6", "::1", 9, false},
		{"udp4", "127.0.0.1", 17, true}, {"udp6", "::1", 19, true}} {
		t.Run(fmt.Sprintf("%s/configuration=%t", family.network, family.configuration), func(t *testing.T) {
			installEpoch := install
			epochMap, epochSet := ownershipEpochMap, ownershipEpochSet
			if family.configuration {
				installEpoch = installConfiguration
				epochMap, epochSet = configurationEpochMap, configurationEpochSet
				revocation, err := prepareOwnershipClear(ctx)
				if err != nil {
					t.Fatal(err)
				}
				executeGuardFixture(ctx, t, revocation.batch.data)
			}
			installEpoch(t, family.epoch)
			channelMap, egressSet := epochChannelNames(family.configuration)
			probeExists := false
			dropProbe := func() {
				if !probeExists {
					return
				}
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				defer cancel()
				packetNft(cleanup, t, "flush chain inet "+ownedTable+" epoch_probe; delete chain inet "+ownedTable+" epoch_probe; "+
					"flush chain inet "+ownedTable+" save_owner_priority; delete chain inet "+ownedTable+" save_owner_priority")
				packetNft(cleanup, t, "flush chain netdev "+ownedTable+" epoch_probe; delete chain netdev "+ownedTable+" epoch_probe; "+
					"flush chain netdev "+ownedTable+" epoch_restored; delete chain netdev "+ownedTable+" epoch_restored; "+
					"flush chain netdev "+ownedTable+" restore_owner_priority; delete chain netdev "+ownedTable+" restore_owner_priority")
				probeExists = false
			}
			t.Cleanup(dropProbe)
			server, err := (&net.ListenConfig{}).ListenPacket(ctx, family.network, net.JoinHostPort(family.address, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			}()
			udp, ok := server.(*net.UDPConn)
			if !ok {
				t.Fatal("UDP fixture returned another connection type")
			}
			setPriority := func(t *testing.T, priority int) {
				t.Helper()
				raw, err := udp.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var optionErr error
				if err := raw.Control(func(fd uintptr) {
					optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PRIORITY, priority) // #nosec G115 -- socket descriptors fit the platform int.
				}); err != nil || optionErr != nil {
					t.Fatal("socket priority fixture failed", err, optionErr)
				}
			}
			setPriority(t, 5)
			listener, ok := server.LocalAddr().(*net.UDPAddr)
			if !ok {
				t.Fatal("UDP fixture returned another address type")
			}
			port := listener.Port
			priorityHelpers := "table inet " + ownedTable + " {\n" + strings.Join(ownerPriorityRules(false), "\n") + "\n}\n" +
				"table netdev " + ownedTable + " {\n" + strings.Join(ownerPriorityRules(true), "\n") + "\n}\n"
			physicalProbe := fmt.Sprintf("add chain netdev %s epoch_probe { type filter hook egress device lo priority -50; policy accept; };\n"+
				"add rule netdev %s epoch_probe udp sport %d meta mark & 0xffffe3ff == 0xb1370025 meta priority @%s jump restore_owner_priority;\n"+
				"add rule netdev %s epoch_probe udp sport %d drop;\n"+
				"add chain netdev %s epoch_restored { type filter hook egress device lo priority 50; policy accept; };\n"+
				"add rule netdev %s epoch_restored udp sport %d meta priority 5 meta mark 0xb1370025 accept;\n"+
				"add rule netdev %s epoch_restored udp sport %d drop;\n",
				ownedTable, ownedTable, port, egressSet, ownedTable, port, ownedTable, ownedTable, port, ownedTable, port)
			// This temporary probe exercises only code-owned epoch objects and
			// priority helpers. It is not the router's owner-access implementation.
			createProbe := func(stamp bool) {
				t.Helper()
				program := priorityHelpers + fmt.Sprintf("add chain inet %s epoch_probe { type filter hook output priority -150; policy accept; };\n", ownedTable)
				if stamp {
					program += fmt.Sprintf("add rule inet %s epoch_probe udp dport %d ct direction original ct mark set meta nfproto map @%s ct mark set ct mark | 37;\n",
						ownedTable, port, epochMap)
				}
				prefix := fmt.Sprintf("add rule inet %s epoch_probe udp sport %d ct direction reply ct mark & %#x @%s ct mark & %#x == 37 ",
					ownedTable, port, ownershipEpochMask, epochSet, ownershipRuleMask)
				// A jump ends its rule. Return from the save helper continues
				// at the next rule, which rechecks the same admitted epoch.
				program += prefix + "meta mark set 0xb1370025 jump save_owner_priority;\n"
				program += prefix + fmt.Sprintf("meta mark & 0xffffe3ff == 0xb1370025 meta priority set ct mark & %#x map @%s accept;\n", ownershipEpochMask, channelMap)
				program += fmt.Sprintf("add rule inet %s epoch_probe udp sport %d ct direction reply drop;\n", ownedTable, port)
				packetNft(ctx, t, program+physicalProbe)
				probeExists = true
			}
			createProbe(true)
			client, err := (&net.ListenConfig{}).ListenPacket(ctx, family.network, net.JoinHostPort(family.address, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			}()
			if _, err := client.WriteTo([]byte("initial"), server.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			if _, _, err := server.ReadFrom(buffer); err != nil {
				t.Fatal(err)
			}
			reply := func(t *testing.T, wanted bool) {
				t.Helper()
				if _, err := server.WriteTo([]byte("reply"), client.LocalAddr()); err != nil &&
					(wanted || !errors.Is(err, syscall.EPERM)) {
					t.Fatal(err)
				}
				if err := client.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				_, _, err := client.ReadFrom(buffer)
				if wanted && err != nil {
					t.Fatal("current connection epoch did not return", err)
				}
				if !wanted {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatal("an old connection survived epoch revocation", err)
					}
				}
			}
			for priority := 0; priority <= 7; priority++ {
				t.Run(fmt.Sprintf("priority=%d", priority), func(t *testing.T) {
					setPriority(t, priority)
					packetNft(ctx, t, fmt.Sprintf("flush chain netdev %s epoch_restored; "+
						"add rule netdev %s epoch_restored udp sport %d meta priority %d meta mark 0xb1370025 accept; "+
						"add rule netdev %s epoch_restored udp sport %d drop;", ownedTable, ownedTable, port, priority, ownedTable, port))
					reply(t, true)
				})
			}
			for _, priority := range []int{8, 0x10005} {
				setPriority(t, priority)
				reply(t, false)
			}
			setPriority(t, 5)
			packetNft(ctx, t, fmt.Sprintf("flush chain netdev %s epoch_restored; "+
				"add rule netdev %s epoch_restored udp sport %d meta priority 5 meta mark 0xb1370025 accept; "+
				"add rule netdev %s epoch_restored udp sport %d drop;", ownedTable, ownedTable, port, ownedTable, port))
			reply(t, true)
			packetNft(ctx, t, "flush set netdev "+ownedTable+" "+egressSet)
			reply(t, false)
			dropProbe()
			installEpoch(t, family.epoch)
			createProbe(false)
			reply(t, true)
			if family.configuration {
				revocation, err := prepareOwnershipClear(ctx)
				if err != nil {
					t.Fatal(err)
				}
				executeGuardFixture(ctx, t, revocation.batch.data)
				reply(t, true)
			}
			dropProbe()
			installEpoch(t, family.epoch+1)
			createProbe(false)
			reply(t, false)
			dropProbe()
		})
	}
	now := time.Now().UTC()
	old := now.Add(-80 * time.Second)
	proof, err := ownershipProofFixture(t, baseline, old, 90*time.Second).InEpoch(ctx, 11)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareOwnership(ctx, proof, now)
	if err != nil || prepared.epochTimeout > 5 {
		t.Fatal("fixture did not retain the original epoch observation deadline", err)
	}
	if err := validateOwnershipPreparation(ctx, prepared, now); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, prepared.batch.data)
	timer := time.NewTimer(time.Duration(prepared.epochTimeout+1) * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	listing, err := p.execute(ctx, inspectOwned, nil)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := layout.inspectTable(ctx, "inet", listing)
	if err != nil || len(observed.sets[ownershipEpochSet].Elements) != 0 || len(observed.sets[ownershipEpochMap].Elements) != 0 {
		t.Fatal("kernel retained an epoch beyond its original producer deadline", err)
	}
	revocation, err := prepareOwnershipClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, revocation.batch.data)
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		t.Fatal("epoch revocation damaged fixed guard objects", err)
	}
	configurationClear, err := prepareConfigurationClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = p.run(ctx, commandInput{op: applyConfiguration, configuration: configurationClear})
	p.release()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		t.Fatal("configuration revocation damaged fixed guard objects", err)
	}
}
