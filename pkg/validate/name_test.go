package validate

import (
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "alphanumeric", input: "prod1", want: "prod1"},
		{name: "underscore and dash", input: "us_east-1", want: "us_east-1"},
		{name: "trims surrounding space", input: "  default\n", want: "default"},
		{name: "max length", input: strings.Repeat("a", MaxNameLength), want: strings.Repeat("a", MaxNameLength)},
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace only", input: "   ", wantErr: true},
		{name: "too long", input: strings.Repeat("a", MaxNameLength+1), wantErr: true},
		{name: "inner space", input: "prod network", wantErr: true},
		{name: "dot", input: "prod.network", wantErr: true},
		{name: "slash", input: "prod/../etc", wantErr: true},
		{name: "non-ascii", input: "prodé", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Name("agent-network", tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Name(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Name(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "already valid", input: "pd-agent_1", want: "pd-agent_1"},
		{name: "macos bonjour hostname", input: "MacBook-Pro-3.local", want: "MacBook-Pro-3"},
		{name: "ec2 internal fqdn", input: "ip-10-0-1-5.ec2.internal", want: "ip-10-0-1-5"},
		{name: "spaces", input: "My Box", want: "My-Box"},
		{name: "collapses runs", input: "my   box!!!name", want: "my-box-name"},
		{name: "trims edge dashes", input: " !box! ", want: "box"},
		{name: "keeps existing dash run", input: "a--b", want: "a--b"},
		{name: "truncates and trims", input: strings.Repeat("a", MaxNameLength) + "-tail", want: strings.Repeat("a", MaxNameLength)},
		{name: "leading dot keeps whole value", input: ".hidden host", want: "hidden-host"},
		{name: "all invalid", input: "..!!", want: ""},
		{name: "non-ascii", input: "बॉक्स", want: ""},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeName(tt.input)
			if got != tt.want {
				t.Fatalf("SanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if got == "" {
				return
			}
			if _, err := Name("agent-name", got); err != nil {
				t.Errorf("SanitizeName(%q) = %q, not a valid name: %v", tt.input, got, err)
			}
		})
	}
}
