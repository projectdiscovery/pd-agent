package runtools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunHttpx_RequiresOutputFile(t *testing.T) {
	_, _, err := RunHttpx(context.Background(), []string{"example.com"}, HttpxOptions{})
	if err == nil {
		t.Fatal("expected error when OutputFile is empty")
	}
}

// TestRunHttpx_NoTargets exercises defaults and confirms an empty input list
// completes without erroring. Output file may or may not be created depending
// on whether httpx writes a header — we only care that the call returns clean.
func TestRunHttpx_NoTargets(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "httpx.jsonl")

	got, urls, err := RunHttpx(context.Background(), nil, HttpxOptions{OutputFile: outFile})
	if err != nil {
		t.Fatalf("RunHttpx(no targets) returned error: %v", err)
	}
	if got != outFile {
		t.Errorf("output path mismatch: got %q want %q", got, outFile)
	}
	if len(urls) != 0 {
		t.Errorf("expected no URLs, got %v", urls)
	}
	// Output file is optional for empty input; if it exists, must be empty.
	if info, err := os.Stat(outFile); err == nil && info.Size() != 0 {
		t.Errorf("expected empty output file, got %d bytes", info.Size())
	}
}
