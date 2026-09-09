package scanlog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadEmptyFile(t *testing.T) {
	srv := newScanLogServer(t)
	outputFile := writeOutput(t, "")

	if err := uploadToPlatform(context.Background(), outputFile); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if n := len(srv.presigns()); n != 0 {
		t.Errorf("presign requests = %d, want 0 for an empty output", n)
	}
	if n := len(srv.puts()); n != 0 {
		t.Errorf("PUT requests = %d, want 0 for an empty output", n)
	}
}

func TestUploadMissingFile(t *testing.T) {
	newScanLogServer(t)
	missing := filepath.Join(t.TempDir(), "absent.jsonl")

	err := uploadToPlatform(context.Background(), missing)
	if err == nil {
		t.Fatal("expected an error for a missing output file")
	}
	if !strings.Contains(err.Error(), "stat output") {
		t.Errorf("error = %v, want it to mention stat output", err)
	}
}

func TestGzipFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.jsonl")
	dst := filepath.Join(dir, "out.gz")

	content := strings.Repeat(testScanLogLine, 200)
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	size, err := gzipFile(src, dst)
	if err != nil {
		t.Fatalf("gzipFile: %v", err)
	}

	st, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if size != st.Size() {
		t.Errorf("returned size = %d, want %d", size, st.Size())
	}
	if size >= int64(len(content)) {
		t.Errorf("gz size %d not smaller than raw %d", size, len(content))
	}

	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if got := gunzip(t, raw); got != content {
		t.Error("round-tripped content differs from source")
	}
}

func TestGzipFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	if _, err := gzipFile(filepath.Join(dir, "absent"), filepath.Join(dir, "out.gz")); err == nil {
		t.Fatal("expected an error for a missing source")
	}
}

func TestDestinations(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		t.Setenv("PDCP_ENABLE_SCAN_LOG_UPLOAD", "")
		if got := Destinations(); len(got) != 0 {
			t.Errorf("Destinations() = %d, want 0 when the toggle is unset", len(got))
		}
	})

	t.Run("platform when enabled", func(t *testing.T) {
		t.Setenv("PDCP_ENABLE_SCAN_LOG_UPLOAD", "true")
		got := Destinations()
		if len(got) != 1 {
			t.Fatalf("Destinations() = %d, want 1", len(got))
		}
		if got[0].Name() != "pdcp" {
			t.Errorf("destination = %q, want pdcp", got[0].Name())
		}
	})
}

// fakeUploader records what the orchestrator handed it.
type fakeUploader struct {
	name    string
	err     error
	calls   int
	gzBytes []byte
	gzSize  int64
}

func (f *fakeUploader) Name() string { return f.name }

func (f *fakeUploader) Upload(_ context.Context, _ Meta, gzPath string, gzSize int64) (string, error) {
	f.calls++
	f.gzSize = gzSize
	f.gzBytes, _ = os.ReadFile(gzPath)
	if f.err != nil {
		return "", f.err
	}
	return "loc://" + f.name, nil
}

func TestUploadNoDestinations(t *testing.T) {
	outputFile := writeOutput(t, testScanLogLine)
	if err := Upload(context.Background(), nil, testMeta(), outputFile); err != nil {
		t.Fatalf("Upload with no destinations: %v", err)
	}
}

// One gzip, every destination, and a failing destination must not stop the rest.
func TestUploadFansOutToEveryDestination(t *testing.T) {
	a := &fakeUploader{name: "a"}
	b := &fakeUploader{name: "b", err: errors.New("bucket on fire")}
	c := &fakeUploader{name: "c"}
	outputFile := writeOutput(t, testScanLogLine)

	err := Upload(context.Background(), []Uploader{a, b, c}, testMeta(), outputFile)
	if err == nil {
		t.Fatal("expected the failing destination to surface an error")
	}
	if !strings.Contains(err.Error(), "b: bucket on fire") {
		t.Errorf("error = %v, want it to name destination b", err)
	}
	if strings.Contains(err.Error(), "a:") || strings.Contains(err.Error(), "c:") {
		t.Errorf("error = %v, must only name the failing destination", err)
	}
	for _, u := range []*fakeUploader{a, b, c} {
		if u.calls != 1 {
			t.Errorf("destination %s called %d times, want 1", u.name, u.calls)
		}
	}
	if got := gunzip(t, a.gzBytes); got != testScanLogLine {
		t.Errorf("destination a got %q, want the gzipped output", got)
	}
	if a.gzSize != int64(len(a.gzBytes)) {
		t.Errorf("gzSize = %d, want %d", a.gzSize, len(a.gzBytes))
	}
	if string(a.gzBytes) != string(c.gzBytes) {
		t.Error("destinations received different bytes; the output should be gzipped once")
	}
}

func TestUploadRemovesGzTempOnFailure(t *testing.T) {
	outputFile := writeOutput(t, testScanLogLine)
	failing := &fakeUploader{name: "x", err: errors.New("nope")}

	if err := Upload(context.Background(), []Uploader{failing}, testMeta(), outputFile); err == nil {
		t.Fatal("expected an error")
	}

	entries, err := os.ReadDir(filepath.Dir(outputFile))
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			t.Errorf("leftover gz temp after a failed upload: %s", e.Name())
		}
	}
}
