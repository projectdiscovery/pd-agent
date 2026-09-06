package runtools

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func TestFilterDeniedProbePorts(t *testing.T) {
	tests := []struct {
		name        string
		in          []string
		wantKept    []string
		wantDropped []string
	}{
		{"nil", nil, []string{}, nil},
		{"bare host kept", []string{"printer.local"}, []string{"printer.local"}, nil},
		{"9100 dropped", []string{"10.0.0.5:9100"}, []string{}, []string{"10.0.0.5:9100"}},
		{"range edges", []string{"h:9099", "h:9100", "h:9107", "h:9108"}, []string{"h:9099", "h:9108"}, []string{"h:9100", "h:9107"}},
		{"ipv6 dropped", []string{"[fe80::1]:9100", "[fe80::1]:443"}, []string{"[fe80::1]:443"}, []string{"[fe80::1]:9100"}},
		{"web ports kept", []string{"h:80", "h:443", "h:8443"}, []string{"h:80", "h:443", "h:8443"}, nil},
		{"garbage kept", []string{"h:notaport", ""}, []string{"h:notaport", ""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, dropped := FilterDeniedProbePorts(tt.in)
			if !reflect.DeepEqual(kept, tt.wantKept) {
				t.Errorf("kept = %v, want %v", kept, tt.wantKept)
			}
			if !reflect.DeepEqual(dropped, tt.wantDropped) {
				t.Errorf("dropped = %v, want %v", dropped, tt.wantDropped)
			}
		})
	}
}

func TestDeniedProbePortSets(t *testing.T) {
	if got := len(DeniedProbePorts()); got != 8 {
		t.Fatalf("DeniedProbePorts len = %d, want 8", got)
	}
	if got := len(DeniedProbePortStrings()); got != 8 {
		t.Fatalf("DeniedProbePortStrings len = %d, want 8", got)
	}
	for p := 9100; p <= 9107; p++ {
		if !IsDeniedProbePort(p) {
			t.Errorf("IsDeniedProbePort(%d) = false", p)
		}
	}
	for _, p := range []int{80, 443, 9099, 9108} {
		if IsDeniedProbePort(p) {
			t.Errorf("IsDeniedProbePort(%d) = true", p)
		}
	}
}

func TestStripDeniedProbePorts(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, []string{}},
		{"bare host kept", []string{"h"}, []string{"h"}},
		{"denied port stripped to host", []string{"10.0.0.5:9100"}, []string{"10.0.0.5"}},
		{"dedupe after strip", []string{"h", "h:9100", "h:9107"}, []string{"h"}},
		{"allowed port kept", []string{"h:443", "h:9100"}, []string{"h:443", "h"}},
		{"ipv6", []string{"[fe80::1]:9100"}, []string{"fe80::1"}},
		{"whitespace denied port", []string{" \t10.0.0.5:9100 \r\n"}, []string{"10.0.0.5"}},
		{"whitespace ipv6", []string{"\t[fe80::1]:9107 "}, []string{"fe80::1"}},
		{"whitespace dedupe", []string{" h ", "h:9100 ", "\th:9107"}, []string{"h"}},
		{"whitespace allowed port", []string{" h:443 "}, []string{"h:443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripDeniedProbePorts(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChromeHostResolverRules(t *testing.T) {
	got := ChromeHostResolverRules()
	want := "MAP *:9100 ~NOTFOUND,MAP *:9101 ~NOTFOUND,MAP *:9102 ~NOTFOUND,MAP *:9103 ~NOTFOUND,MAP *:9104 ~NOTFOUND,MAP *:9105 ~NOTFOUND,MAP *:9106 ~NOTFOUND,MAP *:9107 ~NOTFOUND"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestFastdialerDefaultOptionsCarryDenyList(t *testing.T) {
	have := make(map[int]struct{}, len(fastdialer.DefaultOptions.DenyPortList))
	for _, p := range fastdialer.DefaultOptions.DenyPortList {
		have[p] = struct{}{}
	}
	for p := 9100; p <= 9107; p++ {
		if _, ok := have[p]; !ok {
			t.Errorf("fastdialer.DefaultOptions.DenyPortList missing %d", p)
		}
	}
}
