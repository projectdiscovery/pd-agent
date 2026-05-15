package runtools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

func TestParseTlsxTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		host string
		port string
	}{
		{"bare host", "example.com", "example.com", "443"},
		{"host with port", "example.com:8443", "example.com", "8443"},
		{"ipv4 with port", "10.0.0.1:443", "10.0.0.1", "443"},
		{"empty input", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, p := parseTlsxTarget(tc.in)
			if h != tc.host || p != tc.port {
				t.Errorf("parseTlsxTarget(%q) = (%q, %q); want (%q, %q)",
					tc.in, h, p, tc.host, tc.port)
			}
		})
	}
}

func TestRunTlsx_NoTargets(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "tlsx.jsonl")

	got, err := RunTlsx(context.Background(), nil, TlsxOptions{OutputFile: outFile})
	if err != nil {
		t.Fatalf("RunTlsx(no targets) returned error: %v", err)
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

func TestRunTlsx_RequiresOutputFile(t *testing.T) {
	_, err := RunTlsx(context.Background(), []string{"example.com"}, TlsxOptions{})
	if err == nil {
		t.Fatal("expected error when OutputFile is empty")
	}
}

// TestResponseSerialization guards JSONL output: fails if tlsx's Response
// stops round-tripping through JSON.
func TestResponseSerialization(t *testing.T) {
	resp := &clients.Response{
		Host:        "example.com",
		Port:        "443",
		ProbeStatus: true,
		Version:     "tls13",
		Cipher:      "TLS_AES_128_GCM_SHA256",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got clients.Response
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Host != resp.Host || got.Port != resp.Port || got.Version != resp.Version {
		t.Errorf("roundtrip lost fields: got %+v want %+v", got, resp)
	}
}
