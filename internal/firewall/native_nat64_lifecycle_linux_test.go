package firewall

import (
	"context"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/agent"
	"github.com/lanrith/router-policy-agent/internal/state"
)

type testNAT64Supervisor struct {
	activationsValue []nativeNAT64Activation
	err              error
}

func (supervisor *testNAT64Supervisor) activations(context.Context, []*nativeNAT64Transport) ([]nativeNAT64Activation, error) {
	return supervisor.activationsValue, supervisor.err
}

func nat64ServiceOptions() serviceOptions {
	options := serviceOptionsFixture()
	options.state.AdvanceOwnershipEpoch = func(context.Context) (uint32, error) { return 1, nil }
	return options
}

func TestGuardedServiceRequiresSupervisorExactlyForSelectedNAT64Runtime(t *testing.T) {
	t.Parallel()
	nat64Backend := aggregateNAT64BackendFixture(t)
	options := nat64ServiceOptions()
	if service, err := nat64Backend.newService(options); err == nil || service != nil {
		t.Fatal("enforcing NAT64 profile started without a translator supervisor")
	}
	options.nat64 = &testNAT64Supervisor{}
	service, err := nat64Backend.newService(options)
	if err != nil || service == nil {
		t.Fatal("enforcing NAT64 profile rejected its trusted supervisor", err)
	}

	ordinary, err := newGuardedBackend(backendOptionsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	ordinaryOptions := serviceOptionsFixture()
	ordinaryOptions.nat64 = &testNAT64Supervisor{}
	if service, err := ordinary.newService(ordinaryOptions); err == nil || service != nil {
		t.Fatal("profile without NAT64 retained an unused translator supervisor")
	}

	shadow := nat64ServiceOptions()
	shadow.mode = agent.Shadow
	shadow.state.AdvanceOwnershipEpoch = nil
	shadow.nat64 = &testNAT64Supervisor{}
	if service, err := nat64Backend.newService(shadow); err == nil || service != nil {
		t.Fatal("shadow service retained a privileged translator supervisor")
	}
	shadow.nat64 = nil
	shadow.state = agent.Persistence{
		Load: func(context.Context) (state.Document, error) { return state.Initial(), nil },
		Save: func(context.Context, state.Document) error { return nil },
	}
	if service, err := nat64Backend.newService(shadow); err != nil || service == nil {
		t.Fatal("shadow NAT64 profile required unused activation authority", err)
	}
}
