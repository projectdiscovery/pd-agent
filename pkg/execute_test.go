package pkg

import (
	"path/filepath"
	"slices"
	"testing"
)

// The policy this pins: an unresolved template drops and the chunk scans the
// rest, rather than the chunk aborting and losing coverage the agent does have.
func TestResolveRequestedTemplates(t *testing.T) {
	// A real absolute path: a "/tmp/..." literal is not private on Windows,
	// where filepath.IsAbs calls it relative.
	priv := filepath.Join(t.TempDir(), "chunk", "private.yaml")

	tests := []struct {
		name       string
		requested  []string
		missing    []string
		requireAll bool
		wantKept   []string
		wantErr    bool
	}{
		{
			name:      "partial resolution scans the rest",
			requested: []string{"http/a.yaml", "http/gone.yaml", "http/b.yaml"},
			missing:   []string{"http/gone.yaml"},
			wantKept:  []string{"http/a.yaml", "http/b.yaml"},
		},
		{
			// Nothing left to run, so there is no partial scan to salvage.
			name:      "nothing resolves is an error",
			requested: []string{"a.yaml", "b.yaml"},
			missing:   []string{"a.yaml", "b.yaml"},
			wantErr:   true,
		},
		{
			name:       "requireAll fails on a single unresolved template",
			requested:  []string{"a.yaml", "gone.yaml"},
			missing:    []string{"gone.yaml"},
			requireAll: true,
			wantErr:    true,
		},
		{
			name:      "private templates drop like any other",
			requested: []string{priv, "http/a.yaml"},
			missing:   []string{priv},
			wantKept:  []string{"http/a.yaml"},
		},
		{
			name:      "duplicate entries all drop",
			requested: []string{"a.yaml", "gone.yaml", "gone.yaml", "b.yaml"},
			missing:   []string{"gone.yaml"},
			wantKept:  []string{"a.yaml", "b.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, err := resolveRequestedTemplates(tt.requested, tt.missing, tt.requireAll)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveRequestedTemplates(...) error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !slices.Equal(kept, tt.wantKept) {
				t.Errorf("kept = %v, want %v", kept, tt.wantKept)
			}
		})
	}
}

// missingTemplates deduplicates, so len(missing) undercounts what was actually
// removed. Coverage arithmetic has to come from the surviving list.
func TestResolveRequestedTemplatesDroppedCountSurvivesDuplicates(t *testing.T) {
	requested := []string{"a.yaml", "gone.yaml", "gone.yaml", "b.yaml"}
	missing := []string{"gone.yaml"}

	kept, err := resolveRequestedTemplates(requested, missing, false)
	if err != nil {
		t.Fatalf("resolveRequestedTemplates: %v", err)
	}
	if dropped := len(requested) - len(kept); dropped != 2 {
		t.Errorf("dropped = %d, want 2; len(missing) = %d undercounts", dropped, len(missing))
	}
}

func TestCountPrivate(t *testing.T) {
	// Real temp paths, not "/tmp/..." literals: countPrivate keys off
	// filepath.IsAbs, which calls a unix-shaped path relative on Windows.
	dir := t.TempDir()
	got := countPrivate([]string{
		"http/a.yaml",
		filepath.Join(dir, "chunk", "p1.yaml"),
		filepath.Join(dir, "chunk", "p2.yaml"),
	})
	if got != 2 {
		t.Errorf("countPrivate = %d, want 2", got)
	}
}
