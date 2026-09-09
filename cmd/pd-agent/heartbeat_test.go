package main

import (
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestHeartbeatQuery(t *testing.T) {
	options := &Options{
		AgentId:      "d0abcd1234567890abcd",
		AgentName:    "shubham-mac",
		AgentNetwork: "shubham-mac",
	}

	got := heartbeatQuery(options, "v1.2.3", []string{"192.168.0.0/24", "10.0.0.0/8"})

	want := map[string]string{
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"id":              "d0abcd1234567890abcd",
		"name":            "shubham-mac",
		"agent_network":   "shubham-mac",
		"version":         "v1.2.3",
		"network_subnets": "192.168.0.0/24,10.0.0.0/8",
	}
	for key, wantValue := range want {
		if gotValue := got.Get(key); gotValue != wantValue {
			t.Errorf("%s = %q, want %q", key, gotValue, wantValue)
		}
	}
	if len(got) != len(want) {
		t.Errorf("query has %d params, want %d: %v", len(got), len(want), got)
	}
}

// The platform reads the running build off the heartbeat, so the parameter has
// to survive every code path, including a dev binary with no ldflags stamp.
func TestHeartbeatQueryAlwaysCarriesVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{name: "release build", version: "v1.4.0"},
		{name: "unstamped dev build", version: "dev"},
		{name: "empty", version: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := heartbeatQuery(&Options{}, tt.version, nil)
			if _, present := got["version"]; !present {
				t.Fatalf("version parameter absent for %q", tt.version)
			}
			if got.Get("version") != tt.version {
				t.Errorf("version = %q, want %q", got.Get("version"), tt.version)
			}
		})
	}
}

func TestHeartbeatQueryOmitsEmptySubnets(t *testing.T) {
	for _, subnets := range [][]string{nil, {}} {
		got := heartbeatQuery(&Options{}, "v1.0.0", subnets)
		if _, present := got["network_subnets"]; present {
			t.Errorf("network_subnets present for %v, want it omitted", subnets)
		}
	}
}

// A name or network with a space or slash must not corrupt the query.
func TestHeartbeatQueryEncodesValues(t *testing.T) {
	options := &Options{AgentId: "id/1", AgentName: "a b", AgentNetwork: "n&m"}
	encoded := heartbeatQuery(options, "v1.0.0", nil).Encode()

	parsed, err := url.ParseQuery(encoded)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", encoded, err)
	}
	if parsed.Get("name") != "a b" || parsed.Get("agent_network") != "n&m" || parsed.Get("id") != "id/1" {
		t.Errorf("round-trip lost values: %v", parsed)
	}
	if strings.Contains(encoded, " ") {
		t.Errorf("encoded query contains a raw space: %q", encoded)
	}
}
