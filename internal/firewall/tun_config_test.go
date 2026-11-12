package firewall

import (
	"testing"

	"github.com/lanrith/router-policy-agent/internal/agent"
)

func TestHelperConfigTUNSelectsDataPublisherWithoutAllocatorSupervisor(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*helperConfig)
		valid  bool
	}{
		{"native TUN", func(*helperConfig) {}, true},
		{"missing conntrack", func(c *helperConfig) { c.ConntrackExecutable = "" }, false},
		{"legacy supervisor", func(c *helperConfig) { c.NAT64Runtime = &c.Profile }, false},
		{"shadow unsupported", func(c *helperConfig) { c.Mode = agent.Shadow }, false},
		{"unknown backend", func(c *helperConfig) { c.Backend = "other" }, false},
		{"tool without backend", func(c *helperConfig) { c.Backend = "" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := helperConfigFixture()
			c.Backend = "tun"
			c.ConntrackExecutable = "/usr/sbin/conntrack"
			test.change(&c)
			_, err := decodeHelperConfig(t.Context(), helperConfigBytes(t, c))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v: %v", test.valid, err)
			}
		})
	}
}
