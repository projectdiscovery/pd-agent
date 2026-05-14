package runtools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	retryabledns "github.com/projectdiscovery/retryabledns"
)

func TestRunDnsx_NoTargets(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "dnsx.jsonl")

	got, err := RunDnsx(context.Background(), nil, DnsxOptions{OutputFile: outFile})
	if err != nil {
		t.Fatalf("RunDnsx(no targets) returned error: %v", err)
	}
	if got != outFile {
		t.Errorf("output path mismatch: got %q want %q", got, outFile)
	}
	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty output file, got %d bytes", info.Size())
	}
}

func TestRunDnsx_RequiresOutputFile(t *testing.T) {
	_, err := RunDnsx(context.Background(), []string{"example.com"}, DnsxOptions{})
	if err == nil {
		t.Fatal("expected error when OutputFile is empty")
	}
}

// TestDNSDataSerialization guards JSONL output: fails if upstream
// retryabledns.DNSData stops round-tripping through JSON.
func TestDNSDataSerialization(t *testing.T) {
	data := &retryabledns.DNSData{
		Host:  "example.com",
		A:     []string{"93.184.216.34"},
		AAAA:  []string{"2606:2800:220:1:248:1893:25c8:1946"},
		CNAME: []string{"example.com.cdn.example.net"},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got retryabledns.DNSData
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Host != data.Host || len(got.A) != 1 || got.A[0] != data.A[0] {
		t.Errorf("roundtrip lost fields: got %+v want %+v", got, data)
	}
}
