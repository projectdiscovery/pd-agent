package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/projectdiscovery/pd-agent/pkg/runtools"
)

// This decides whether an unreachable GitHub grounds a whole fleet, so every
// combination is pinned.
func TestTemplateBootFatal(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		installed string
		want      bool
	}{
		{
			name:      "no error",
			err:       nil,
			installed: "v10.4.8",
			want:      false,
		},
		{
			name:      "freshness unknown with templates on disk",
			err:       fmt.Errorf("%w: api down", runtools.ErrFreshnessUnknown),
			installed: "v10.4.5",
			want:      false,
		},
		{
			name:      "rate limited with templates on disk",
			err:       fmt.Errorf("%w: %w", runtools.ErrFreshnessUnknown, runtools.ErrGitHubRateLimited),
			installed: "v10.4.5",
			want:      false,
		},
		{
			name:      "freshness unknown with no templates",
			err:       fmt.Errorf("%w: api down", runtools.ErrFreshnessUnknown),
			installed: "",
			want:      true,
		},
		{
			name:      "install failed",
			err:       errors.New("install templates: disk full"),
			installed: "",
			want:      true,
		},
		{
			name:      "install failed with a stale set on disk",
			err:       errors.New("fresh install templates: disk full"),
			installed: "v10.4.5",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := templateBootFatal(tt.err, tt.installed); got != tt.want {
				t.Errorf("templateBootFatal(%v, %q) = %v, want %v", tt.err, tt.installed, got, tt.want)
			}
		})
	}
}
