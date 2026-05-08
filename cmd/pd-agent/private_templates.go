package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// materializePrivateTemplates writes each base64-encoded YAML template to a
// per-chunk temp directory and returns the resulting file paths. The returned
// cleanup() removes the temp directory.
//
// templates maps a template name (e.g. "my-check.yaml") to its base64-encoded
// YAML body. Names are sanitized to safe filenames; ".yaml" is appended if
// missing. Files are written in a deterministic order so paths are stable
// across calls (helps reproducibility and tests).
//
// Errors from individual templates are returned as a combined error, but any
// templates that decoded and wrote successfully are still listed in paths so
// the scan can proceed with whatever was usable.
func materializePrivateTemplates(scanID, chunkID string, templates map[string]string) (paths []string, cleanup func(), err error) {
	if len(templates) == 0 {
		return nil, func() {}, nil
	}

	dir, err := os.MkdirTemp("", fmt.Sprintf("pd-agent-priv-%s-%s-*", sanitize(scanID), sanitize(chunkID)))
	if err != nil {
		return nil, func() {}, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	// Sort names so output paths are deterministic.
	names := make([]string, 0, len(templates))
	for n := range templates {
		names = append(names, n)
	}
	sort.Strings(names)

	var failures []string
	for _, name := range names {
		decoded, derr := base64.StdEncoding.DecodeString(templates[name])
		if derr != nil {
			failures = append(failures, fmt.Sprintf("%s: decode: %v", name, derr))
			continue
		}
		fname := safeFilename(name)
		path := filepath.Join(dir, fname)
		if werr := os.WriteFile(path, decoded, 0o600); werr != nil {
			failures = append(failures, fmt.Sprintf("%s: write: %v", name, werr))
			continue
		}
		paths = append(paths, path)
	}

	if len(failures) > 0 {
		err = fmt.Errorf("materialize private templates: %s", strings.Join(failures, "; "))
	}
	return paths, cleanup, err
}

// sanitize keeps the part of an identifier safe for use in directory names.
// Anything outside [A-Za-z0-9._-] becomes "_". Empty input becomes "x".
func sanitize(s string) string {
	if s == "" {
		return "x"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// safeFilename produces a filename safe to write inside a temp directory.
// Any path separators in the input are stripped. ".yaml" is appended if the
// name has no extension.
func safeFilename(name string) string {
	base := filepath.Base(name)
	base = strings.TrimSpace(base)
	base = sanitize(base)
	if base == "" || base == "." || base == ".." {
		base = "template.yaml"
	}
	if filepath.Ext(base) == "" {
		base += ".yaml"
	}
	return base
}
