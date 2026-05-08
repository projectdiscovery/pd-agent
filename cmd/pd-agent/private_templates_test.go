package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleYAML = `id: test-private-template
info:
  name: Test Private Template
  author: pd-agent
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/healthz"
    matchers:
      - type: status
        status:
          - 200
`

func TestMaterializePrivateTemplates_DecodesAndWrites(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(sampleYAML))
	in := map[string]string{
		"my-check.yaml":   encoded,
		"second-check":    encoded, // no extension - should get .yaml appended
		"path/with/slash": encoded, // path separators - should be stripped
	}

	paths, cleanup, err := materializePrivateTemplates("scan-1", "chunk-A", in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(cleanup)

	if got, want := len(paths), len(in); got != want {
		t.Fatalf("path count: got %d, want %d (paths=%v)", got, want, paths)
	}

	for _, p := range paths {
		if !strings.HasSuffix(p, ".yaml") {
			t.Errorf("path %q does not end with .yaml", p)
		}
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if string(body) != sampleYAML {
			t.Errorf("file %s: contents do not match decoded YAML", p)
		}
	}

	// Path-with-slash should have been collapsed to a single basename
	for _, p := range paths {
		base := filepath.Base(p)
		if strings.ContainsAny(base, `/\`) {
			t.Errorf("filename %q still contains a path separator", base)
		}
	}
}

func TestMaterializePrivateTemplates_DeterministicOrder(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(sampleYAML))
	in := map[string]string{
		"c.yaml": encoded,
		"a.yaml": encoded,
		"b.yaml": encoded,
	}

	paths1, cleanup1, err := materializePrivateTemplates("s", "c", in)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	t.Cleanup(cleanup1)

	paths2, cleanup2, err := materializePrivateTemplates("s", "c", in)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	t.Cleanup(cleanup2)

	// Compare basenames (dirs differ since each call uses MkdirTemp).
	bases1 := make([]string, len(paths1))
	bases2 := make([]string, len(paths2))
	for i, p := range paths1 {
		bases1[i] = filepath.Base(p)
	}
	for i, p := range paths2 {
		bases2[i] = filepath.Base(p)
	}
	if strings.Join(bases1, ",") != strings.Join(bases2, ",") {
		t.Errorf("filename order not deterministic: %v vs %v", bases1, bases2)
	}
	if len(bases1) >= 3 && (bases1[0] != "a.yaml" || bases1[1] != "b.yaml" || bases1[2] != "c.yaml") {
		t.Errorf("expected sorted order [a,b,c], got %v", bases1)
	}
}

func TestMaterializePrivateTemplates_PartialFailure(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte(sampleYAML))
	in := map[string]string{
		"good.yaml": good,
		"bad.yaml":  "not-valid-base64!!!",
	}

	paths, cleanup, err := materializePrivateTemplates("s", "c", in)
	t.Cleanup(cleanup)

	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
	if got, want := len(paths), 1; got != want {
		t.Fatalf("expected %d successful path, got %d (paths=%v)", want, got, paths)
	}
	if filepath.Base(paths[0]) != "good.yaml" {
		t.Errorf("expected good.yaml to succeed, got %s", paths[0])
	}
}

func TestMaterializePrivateTemplates_EmptyInput(t *testing.T) {
	paths, cleanup, err := materializePrivateTemplates("s", "c", nil)
	if err != nil {
		t.Fatalf("nil map: %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup must never be nil")
	}
	cleanup() // must not panic
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for nil input, got %d", len(paths))
	}

	paths, cleanup, err = materializePrivateTemplates("s", "c", map[string]string{})
	if err != nil {
		t.Fatalf("empty map: %v", err)
	}
	cleanup()
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for empty input, got %d", len(paths))
	}
}

func TestMaterializePrivateTemplates_CleanupRemovesTempDir(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(sampleYAML))
	paths, cleanup, err := materializePrivateTemplates("s", "c", map[string]string{
		"only.yaml": encoded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}

	dir := filepath.Dir(paths[0])
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("temp dir should exist before cleanup: %v", err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("temp dir should be removed after cleanup: err=%v", err)
	}
}
