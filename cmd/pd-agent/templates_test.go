package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/projectdiscovery/pd-agent/pkg/runtools"
)

// This decides whether a template failure grounds a whole fleet. The error only
// decides whether anything went wrong at all: which error it is carries no
// weight, so the rows below vary the set on disk and use the error kinds only
// to document the situations that reach here.
func TestTemplateBootFatal(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		haveTemplates bool
		want          bool
	}{
		{
			name:          "no error",
			err:           nil,
			haveTemplates: true,
			want:          false,
		},
		{
			name:          "no error and nothing on disk",
			err:           nil,
			haveTemplates: false,
			want:          false,
		},
		{
			name:          "release lookup failed with templates on disk",
			err:           fmt.Errorf("%w: api down", runtools.ErrFreshnessUnknown),
			haveTemplates: true,
			want:          false,
		},
		{
			// The regression: a download that fails leaves the working set
			// untouched, so it is not worth grounding the agent for.
			name:          "install failed with a working set on disk",
			err:           errors.New("download templates: no space left on device"),
			haveTemplates: true,
			want:          false,
		},
		{
			name:          "release lookup failed with nothing on disk",
			err:           fmt.Errorf("%w: api down", runtools.ErrFreshnessUnknown),
			haveTemplates: false,
			want:          true,
		},
		{
			name:          "install failed with nothing on disk",
			err:           errors.New("install templates: disk full"),
			haveTemplates: false,
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := templateBootFatal(tt.err, tt.haveTemplates); got != tt.want {
				t.Errorf("templateBootFatal(%v, %v) = %v, want %v", tt.err, tt.haveTemplates, got, tt.want)
			}
		})
	}
}
