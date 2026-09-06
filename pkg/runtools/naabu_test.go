package runtools

import (
	"context"
	"strconv"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func TestRunNaabu_RequiresOutputFile(t *testing.T) {
	_, err := RunNaabu(context.Background(), []string{"127.0.0.1"}, NaabuOptions{})
	if err == nil {
		t.Fatal("expected error when OutputFile is empty")
	}
}

// Guards against the "invalid port number: 'top'" failure: the control plane
// sends "top-100", which must map to naabu's TopPorts, not the -p list.
func TestSetNaabuPorts(t *testing.T) {
	tests := []struct {
		spec         string
		wantTopPorts string
		wantPorts    string
	}{
		{"top-100", "100", ""},
		{"top-1000", "1000", ""},
		{"full", "full", ""},
		{"80,443", "", "80,443"},
		{"1-1000", "", "1-1000"},
		{"", "", ""},
		{" top-100 ", "100", ""},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			o := &runner.Options{}
			setNaabuPorts(o, tt.spec)
			if o.TopPorts != tt.wantTopPorts {
				t.Errorf("TopPorts = %q, want %q", o.TopPorts, tt.wantTopPorts)
			}
			if o.Ports != tt.wantPorts {
				t.Errorf("Ports = %q, want %q", o.Ports, tt.wantPorts)
			}
		})
	}
}

func TestNewNaabuOptions_NeverContactsProbeDeniedPorts(t *testing.T) {
	for _, sv := range []bool{false, true} {
		o := newNaabuOptions([]string{"h", "h:9100", "h:443", "[::1]:9107"}, NaabuOptions{Ports: "top-100", ServiceVersion: sv}, nil)
		if len(o.ExcludePorts) != 8 {
			t.Fatalf("ServiceVersion=%v ExcludePorts = %v, want 9100-9107", sv, o.ExcludePorts)
		}
		for _, p := range o.ExcludePorts {
			n, err := strconv.Atoi(p)
			if err != nil || !IsDeniedProbePort(n) {
				t.Errorf("unexpected exclude entry %q", p)
			}
		}
		if got := []string(o.Host); len(got) != 3 || got[0] != "h" || got[1] != "h:443" || got[2] != "::1" {
			t.Errorf("ServiceVersion=%v Host = %v, want [h h:443 ::1] (denied port stripped, host kept)", sv, got)
		}
		if o.TopPorts != "100" {
			t.Errorf("TopPorts = %q, want 100 (port spec must survive)", o.TopPorts)
		}
	}
}
