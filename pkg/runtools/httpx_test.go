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
	if info, err := os.Stat(outFile); err == nil && info.Size() != 0 {
		t.Errorf("expected empty output file, got %d bytes", info.Size())
	}
}
