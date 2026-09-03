package scanlog

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testScanLogLine = `{"template-id":"test","host":"example.com","matched-at":"example.com:443"}` + "\n"

type recordedRequest struct {
	method        string
	path          string
	rawQuery      string
	header        http.Header
	body          []byte
	contentLength int64
}

// scanLogServer fakes the platform presign endpoint plus the object store the
// signed URL points at, and records both requests for assertions.
type scanLogServer struct {
	mu       sync.Mutex
	presign  []recordedRequest
	put      []recordedRequest
	srv      *httptest.Server
	response func(putURL string) (int, any)
	putCode  int
	putBody  string
}

func newScanLogServer(t *testing.T) *scanLogServer {
	t.Helper()

	s := &scanLogServer{putCode: http.StatusOK}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/scans/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.record(&s.presign, r, body)

		code, payload := http.StatusOK, any(signedUploadResponse{
			UploadURL: s.srv.URL + "/objects/scan-log.jsonl.gz",
			Method:    http.MethodPut,
			Headers:   map[string]string{"Content-Type": "application/octet-stream"},
		})
		if s.response != nil {
			code, payload = s.response(s.srv.URL + "/objects/scan-log.jsonl.gz")
		}
		w.WriteHeader(code)
		if raw, ok := payload.(string); ok {
			_, _ = w.Write([]byte(raw))
			return
		}
		_ = json.NewEncoder(w).Encode(payload)
	})

	mux.HandleFunc("/objects/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.record(&s.put, r, body)
		w.WriteHeader(s.putCode)
		if s.putBody != "" {
			_, _ = w.Write([]byte(s.putBody))
		}
	})

	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)

	t.Setenv("PDCP_API_SERVER", s.srv.URL)
	t.Setenv("PDCP_API_KEY", "test-api-key")
	t.Setenv("PROXY_URL", "")

	return s
}

func (s *scanLogServer) record(into *[]recordedRequest, r *http.Request, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*into = append(*into, recordedRequest{
		method:        r.Method,
		path:          r.URL.Path,
		rawQuery:      r.URL.RawQuery,
		header:        r.Header.Clone(),
		body:          body,
		contentLength: r.ContentLength,
	})
}

func (s *scanLogServer) presigns() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.presign...)
}

func (s *scanLogServer) puts() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.put...)
}

func writeOutput(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chunk.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write output: %v", err)
	}
	return path
}

func testMeta() Meta {
	return Meta{
		TeamID:    "team-1",
		ScanID:    "scan-9",
		ChunkID:   "chunk-abc123",
		HistoryID: 42,
	}
}

func uploadToPlatform(ctx context.Context, outputFile string) error {
	return Upload(ctx, []Uploader{NewPlatformUploader()}, testMeta(), outputFile)
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return string(out)
}

func TestPlatformUploader(t *testing.T) {
	srv := newScanLogServer(t)
	outputFile := writeOutput(t, testScanLogLine)

	if err := uploadToPlatform(context.Background(), outputFile); err != nil {
		t.Fatalf("upload: %v", err)
	}

	presigns := srv.presigns()
	if len(presigns) != 1 {
		t.Fatalf("presign requests = %d, want 1", len(presigns))
	}
	p := presigns[0]
	if p.method != http.MethodPost {
		t.Errorf("presign method = %s, want POST", p.method)
	}
	if want := "/v1/scans/scan-9/scan_log/upload-url"; p.path != want {
		t.Errorf("presign path = %s, want %s", p.path, want)
	}
	if want := "history_id=42"; p.rawQuery != want {
		t.Errorf("presign query = %s, want %s", p.rawQuery, want)
	}
	if got := p.header.Get("X-Api-Key"); got != "test-api-key" {
		t.Errorf("presign X-Api-Key = %q, want test-api-key", got)
	}
	if got := p.header.Get("X-Team-Id"); got != "team-1" {
		t.Errorf("presign X-Team-Id = %q, want team-1", got)
	}
	if got := p.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("presign Content-Type = %q, want application/json", got)
	}
	var reqBody map[string]string
	if err := json.Unmarshal(p.body, &reqBody); err != nil {
		t.Fatalf("presign body not JSON: %v", err)
	}
	if want := "chunk-abc123.jsonl.gz"; reqBody["filename"] != want {
		t.Errorf("presign filename = %q, want %q", reqBody["filename"], want)
	}

	puts := srv.puts()
	if len(puts) != 1 {
		t.Fatalf("PUT requests = %d, want 1", len(puts))
	}
	u := puts[0]
	if u.method != http.MethodPut {
		t.Errorf("PUT method = %s, want PUT", u.method)
	}
	if got := u.header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("PUT Content-Type = %q, want the signed header verbatim", got)
	}
	if u.contentLength != int64(len(u.body)) {
		t.Errorf("PUT Content-Length = %d, want %d", u.contentLength, len(u.body))
	}
	if u.contentLength <= 0 {
		t.Error("PUT sent no Content-Length; signed URLs reject chunked bodies")
	}
	if got := gunzip(t, u.body); got != testScanLogLine {
		t.Errorf("uploaded payload = %q, want %q", got, testScanLogLine)
	}

	// The gz temp lives beside the output file; a leaked one would pile up per chunk.
	entries, err := os.ReadDir(filepath.Dir(outputFile))
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			t.Errorf("leftover gz temp file: %s", e.Name())
		}
	}
}

func TestPlatformUploaderPresignFailures(t *testing.T) {
	tests := []struct {
		name     string
		response func(putURL string) (int, any)
		wantErr  string
	}{
		{
			name:     "non-200 status",
			response: func(string) (int, any) { return http.StatusForbidden, "storage not provisioned" },
			wantErr:  "upload-url status 403",
		},
		{
			name:     "unparseable body",
			response: func(string) (int, any) { return http.StatusOK, "not json" },
			wantErr:  "decode upload-url response",
		},
		{
			name:     "missing url",
			response: func(string) (int, any) { return http.StatusOK, signedUploadResponse{Method: http.MethodPut} },
			wantErr:  "missing url/method",
		},
		{
			name: "missing method",
			response: func(putURL string) (int, any) {
				return http.StatusOK, signedUploadResponse{UploadURL: putURL}
			},
			wantErr: "missing url/method",
		},
		{
			name: "payload over max_bytes",
			response: func(putURL string) (int, any) {
				return http.StatusOK, signedUploadResponse{UploadURL: putURL, Method: http.MethodPut, MaxBytes: 1}
			},
			wantErr: "exceeds signed-url max",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newScanLogServer(t)
			srv.response = tt.response
			outputFile := writeOutput(t, testScanLogLine)

			err := uploadToPlatform(context.Background(), outputFile)
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
			if n := len(srv.puts()); n != 0 {
				t.Errorf("PUT requests = %d, want 0 when presign fails", n)
			}
		})
	}
}

func TestPlatformUploaderPutStatus(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		body    string
		wantErr string
	}{
		{name: "200 accepted", code: http.StatusOK},
		{name: "201 accepted", code: http.StatusCreated},
		{name: "403 rejected", code: http.StatusForbidden, body: "SignatureDoesNotMatch", wantErr: "PUT status 403"},
		{name: "500 rejected", code: http.StatusInternalServerError, body: "boom", wantErr: "PUT status 500"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newScanLogServer(t)
			srv.putCode = tt.code
			srv.putBody = tt.body
			outputFile := writeOutput(t, testScanLogLine)

			err := uploadToPlatform(context.Background(), outputFile)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("upload: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("expected an error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A transport failure must not put the signed URL's HMAC query into the error.
func TestPlatformUploaderDoesNotLeakSignature(t *testing.T) {
	const signature = "0123456789abcdefdeadbeef"

	srv := newScanLogServer(t)
	srv.response = func(string) (int, any) {
		return http.StatusOK, signedUploadResponse{
			// Port 1 refuses fast, forcing a *url.Error through stripSignedURL.
			UploadURL: "http://127.0.0.1:1/bucket/obj.gz?X-Amz-Signature=" + signature,
			Method:    http.MethodPut,
		}
	}
	outputFile := writeOutput(t, testScanLogLine)

	err := uploadToPlatform(context.Background(), outputFile)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), signature) {
		t.Errorf("error leaked the URL signature: %v", err)
	}
	if !strings.Contains(err.Error(), "PUT:") {
		t.Errorf("error = %v, want it to name the failed operation", err)
	}
}

func TestStripSignedURL(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    string
		notWant string
	}{
		{
			name: "url error drops the url",
			err: &url.Error{
				Op:  "Put",
				URL: "https://bucket.s3.amazonaws.com/o?X-Amz-Signature=secret",
				Err: errors.New("connection refused"),
			},
			want:    "Put: connection refused",
			notWant: "secret",
		},
		{
			name: "wrapped url error is unwrapped",
			err: fmt.Errorf("PUT: %w", &url.Error{
				Op:  "Put",
				URL: "https://bucket/o?X-Amz-Signature=secret",
				Err: errors.New("timeout"),
			}),
			want:    "Put: timeout",
			notWant: "secret",
		},
		{
			name: "plain error passes through",
			err:  errors.New("no signature here"),
			want: "no signature here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripSignedURL(tt.err)
			if got != tt.want {
				t.Errorf("stripSignedURL() = %q, want %q", got, tt.want)
			}
			if tt.notWant != "" && strings.Contains(got, tt.notWant) {
				t.Errorf("stripSignedURL() = %q, must not contain %q", got, tt.notWant)
			}
		})
	}
}
