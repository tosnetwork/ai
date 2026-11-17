package daemon

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func relayConfig(t *testing.T) Config {
	t.Helper()
	config := testConfig(t)
	publicationFixture(t, &config, time.Unix(1_900_000_000, 0))
	root := filepath.Dir(config.StateDir)
	config.Transport = TransportAgentPacketRelay
	config.Discovery = DiscoveryConfig{Mode: DiscoveryContactFiles, ContactDir: filepath.Join(root, "contacts")}
	config.RelayCarriage = &RelayCarriageConfig{
		CarrySocketPath:   filepath.Join(root, "run", "carrier.sock"),
		ListenSocketPath:  filepath.Join(root, "run", "messenger-carrier.sock"),
		CardPath:          filepath.Join(root, "chat-card.json"),
		EvidenceExportDir: filepath.Join(root, "export"),
	}
	return config
}

func TestRelayCarriageConfigurationIsCheckedAsAWhole(t *testing.T) {
	if err := relayConfig(t).Validate(); err != nil {
		t.Fatalf("valid relay configuration: %v", err)
	}
	cases := map[string]func(*Config){
		"relay without carriage":   func(c *Config) { c.RelayCarriage = nil },
		"carriage without relay":   func(c *Config) { c.Transport = TransportNone },
		"relay with network peers": func(c *Config) { c.Discovery = DiscoveryConfig{Mode: DiscoveryNone} },
		"relay without prekeys":    func(c *Config) { c.Publication = PublicationConfig{Mode: PublicationNone} },
		"relative contact dir":     func(c *Config) { c.Discovery.ContactDir = "contacts" },
		"contact dir with DHT":     func(c *Config) { c.Discovery.DHTGlobalConfigPath = "/etc/global.json" },
		"same sockets":             func(c *Config) { c.RelayCarriage.ListenSocketPath = c.RelayCarriage.CarrySocketPath },
		"socket reused":            func(c *Config) { c.RelayCarriage.ListenSocketPath = c.SocketPath },
		"socket in state dir":      func(c *Config) { c.RelayCarriage.ListenSocketPath = filepath.Join(c.StateDir, "carrier.sock") },
		"relative card":            func(c *Config) { c.RelayCarriage.CardPath = "card.json" },
		"export is contact dir":    func(c *Config) { c.RelayCarriage.EvidenceExportDir = c.Discovery.ContactDir },
		"export inside contacts":   func(c *Config) { c.RelayCarriage.EvidenceExportDir = filepath.Join(c.Discovery.ContactDir, "x") },
		"short re-deposit":         func(c *Config) { c.RelayCarriage.RedepositIntervalSeconds = 599 },
		"long re-deposit":          func(c *Config) { c.RelayCarriage.RedepositIntervalSeconds = 20*3600 + 1 },
		// Its nanosecond product wraps to about 11.6 minutes, which must not
		// pass as an interval.
		"wrapping re-deposit": func(c *Config) { c.RelayCarriage.RedepositIntervalSeconds = 18_446_744_073 + 700 },
		"long timeout":        func(c *Config) { c.RelayCarriage.TimeoutSeconds = 301 },
		"relative MLS driver": func(c *Config) { c.RelayCarriage.MLSDriverPath = "tos-openmls-driver" },
		"MLS driver in state": func(c *Config) { c.RelayCarriage.MLSDriverPath = filepath.Join(c.StateDir, "driver") },
		"MLS timeout alone":   func(c *Config) { c.RelayCarriage.MLSDriverTimeoutSeconds = 5 },
		"long MLS timeout": func(c *Config) {
			c.RelayCarriage.MLSDriverPath, c.RelayCarriage.MLSDriverTimeoutSeconds = "/usr/bin/tos-openmls-driver", 61
		},
		"own relay TTL above 24 h": func(c *Config) { c.RelayCarriage.OwnRelayMaxTTLSeconds = 86_401 },
		"dns contacts": func(c *Config) {
			c.ContactDNS = &ContactDNSConfig{BaseURL: "https://dns.example", BearerTokenFile: "/run/token"}
		},
	}
	for name, mutate := range cases {
		config := relayConfig(t)
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	tests := relayConfig(t)
	tests.RelayCarriage.RedepositIntervalSeconds = 600
	if err := tests.Validate(); err != nil || tests.RelayCarriage.RedepositInterval() != MinRelayRedepositInterval {
		t.Fatalf("shortest test re-deposit interval: %v", err)
	}
	if relayConfig(t).RelayCarriage.RedepositInterval() != 20*time.Hour {
		t.Fatal("default re-deposit interval is not 20 h")
	}
	rooms := relayConfig(t)
	rooms.RelayCarriage.MLSDriverPath = "/usr/bin/tos-openmls-driver"
	if err := rooms.Validate(); err != nil || rooms.RelayCarriage.MLSDriverTimeout() != 10*time.Second {
		t.Fatalf("private rooms over the relay: %v", err)
	}
	if rooms.RoomClockSkew() != time.Duration(rooms.Admission.MaxClockSkewSeconds)*time.Second || rooms.RoomClockSkew() <= 0 {
		t.Fatalf("room clock skew: %v", rooms.RoomClockSkew())
	}
	if rooms.RelayCarriage.OwnRelayMaxTTL() != 86_400 {
		t.Fatalf("default own relay TTL: %d", rooms.RelayCarriage.OwnRelayMaxTTL())
	}
	rooms.RelayCarriage.OwnRelayMaxTTLSeconds = 3_600
	if err := rooms.Validate(); err != nil || rooms.RelayCarriage.OwnRelayMaxTTL() != 3_600 {
		t.Fatalf("a 1 h own relay TTL: %v", err)
	}
	contactFiles := testConfig(t)
	contactFiles.Discovery = DiscoveryConfig{Mode: DiscoveryContactFiles, ContactDir: "/x/contacts"}
	if err := contactFiles.Validate(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("contact-files without relay transport: %v", err)
	}
}
