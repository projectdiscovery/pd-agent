package scanlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetS3ClientCache drops the process-wide client so each test builds its own
// against its own httptest endpoint.
func resetS3ClientCache(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		s3ClientMu.Lock()
		defer s3ClientMu.Unlock()
		s3ClientCfg, s3ClientCached = S3Config{}, nil
	})
	s3ClientMu.Lock()
	defer s3ClientMu.Unlock()
	s3ClientCfg, s3ClientCached = S3Config{}, nil
}

type s3Store struct {
	srv *httptest.Server

	mu     sync.Mutex
	puts   []recordedRequest
	status int
}

func newS3Store(t *testing.T) *s3Store {
	t.Helper()
	s := &s3Store{status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.puts = append(s.puts, recordedRequest{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			header:        r.Header.Clone(),
			body:          body,
			contentLength: r.ContentLength,
		})
		code := s.status
		s.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *s3Store) requests() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.puts...)
}

func (s *s3Store) config() S3Config {
	return S3Config{
		Bucket:       "acme-logs",
		Region:       "us-east-1",
		AccessKeyID:  "AKIAEXAMPLE",
		SecretKey:    "secret",
		Endpoint:     s.srv.URL,
		UsePathStyle: true,
		Prefix:       "scan-logs",
	}
}

func TestS3UploaderPutsTheObject(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)
	outputFile := writeOutput(t, `{"a":1}`+"\n")

	err := Upload(context.Background(), []Uploader{NewS3Uploader(store.config())}, testMeta(), outputFile)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	reqs := store.requests()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(reqs))
	}
	req := reqs[0]

	if req.method != http.MethodPut {
		t.Errorf("method = %s, want PUT", req.method)
	}
	// Path style puts the bucket in the path, so the whole key is assertable.
	if want := "/acme-logs/scan-logs/scan-9/42/chunk-abc123.jsonl.gz"; req.path != want {
		t.Errorf("path = %q, want %q", req.path, want)
	}
	if auth := req.header.Get("Authorization"); !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization = %q, want a SigV4 header", auth)
	}
	// The SDK moves Content-Length off the header map onto the request field,
	// so the header would read empty even on a correctly sized request.
	if req.contentLength != int64(len(req.body)) {
		t.Errorf("ContentLength = %d, want %d", req.contentLength, len(req.body))
	}

	gz, err := gzip.NewReader(strings.NewReader(string(req.body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read gz: %v", err)
	}
	if string(got) != `{"a":1}`+"\n" {
		t.Errorf("uploaded body = %q, want the original JSONL", got)
	}
}

// R2 and GCS interop reject both the checksum header and the aws-chunked body
// the SDK switches to when it sends one. Building Options directly leaves the
// field Unset today, so this guards an SDK bump changing that default.
func TestS3UploaderSendsNoChecksumHeader(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)

	if err := Upload(context.Background(), []Uploader{NewS3Uploader(store.config())},
		testMeta(), writeOutput(t, "line\n")); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	req := store.requests()[0]
	for name := range req.header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-checksum-") {
			t.Errorf("request carries %s, which R2 and GCS reject", name)
		}
	}
	if algo := req.header.Get("X-Amz-Sdk-Checksum-Algorithm"); algo != "" {
		t.Errorf("X-Amz-Sdk-Checksum-Algorithm = %q, want absent", algo)
	}
	if enc := req.header.Get("Content-Encoding"); strings.Contains(enc, "aws-chunked") {
		t.Errorf("Content-Encoding = %q, want no aws-chunked framing", enc)
	}
}

func TestS3UploaderNoPrefix(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)
	cfg := store.config()
	cfg.Prefix = ""

	if err := Upload(context.Background(), []Uploader{NewS3Uploader(cfg)},
		testMeta(), writeOutput(t, "line\n")); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if want := "/acme-logs/scan-9/42/chunk-abc123.jsonl.gz"; store.requests()[0].path != want {
		t.Errorf("path = %q, want %q", store.requests()[0].path, want)
	}
}

func TestS3UploaderPutFailureIsReported(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)
	store.status = http.StatusForbidden
	outputFile := writeOutput(t, "line\n")

	err := Upload(context.Background(), []Uploader{NewS3Uploader(store.config())}, testMeta(), outputFile)
	if err == nil {
		t.Fatal("Upload() = nil, want the 403 reported")
	}
	if !strings.Contains(err.Error(), "s3:") {
		t.Errorf("error = %q, want it prefixed with the destination name", err)
	}

	// The orchestrator must still clean up after a failing destination.
	entries, _ := filepath.Glob(filepath.Join(filepath.Dir(outputFile), "*.gz"))
	if len(entries) != 0 {
		t.Errorf("leftover gz temp files: %v", entries)
	}
}

// The scan and chunk ids come off the NATS work message and land in a key we
// sign ourselves, so a traversal attempt must not reach the bucket at all.
func TestS3UploaderRejectsUntrustedIDs(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)

	tests := []struct {
		name string
		meta Meta
	}{
		{"traversal in scan id", Meta{ScanID: "../../etc", ChunkID: "chunk-1", HistoryID: 1}},
		{"traversal in chunk id", Meta{ScanID: "scan-9", ChunkID: "../../../root", HistoryID: 1}},
		{"separator in chunk id", Meta{ScanID: "scan-9", ChunkID: "a/b", HistoryID: 1}},
		{"empty scan id", Meta{ScanID: "", ChunkID: "chunk-1", HistoryID: 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(store.requests())
			_, err := NewS3Uploader(store.config()).Upload(
				context.Background(), tt.meta, writeOutput(t, "line\n"), 5)
			if err == nil {
				t.Fatal("Upload() = nil, want the id rejected")
			}
			if len(store.requests()) != before {
				t.Error("a request reached the bucket despite the rejected id")
			}
		})
	}
}

func TestS3UploaderName(t *testing.T) {
	if got := NewS3Uploader(S3Config{}).Name(); got != "s3" {
		t.Errorf("Name() = %q, want s3", got)
	}
}

func TestS3UploaderTransportErrorDoesNotLeakSignature(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	cfg := S3Config{
		Bucket:       "acme-logs",
		Region:       "us-east-1",
		AccessKeyID:  "AKIAEXAMPLE",
		SecretKey:    "secret",
		Endpoint:     "http://127.0.0.1:1",
		UsePathStyle: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := NewS3Uploader(cfg).Upload(ctx, testMeta(), writeOutput(t, "line\n"), 5)
	if err == nil {
		t.Fatal("Upload() = nil, want a transport failure")
	}
	for _, leak := range []string{"X-Amz-Signature", "Signature=", "AWS4-HMAC-SHA256", "secret"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
}

func TestS3ClientIsReusedAcrossChunks(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)
	uploader := NewS3Uploader(store.config())

	first := uploader.client()
	if second := NewS3Uploader(store.config()).client(); first != second {
		t.Error("client rebuilt for an identical config; Destinations() runs per chunk")
	}

	changed := store.config()
	changed.Bucket = "other-bucket"
	if rebuilt := NewS3Uploader(changed).client(); rebuilt == first {
		t.Error("client reused after the config changed")
	}
}

func TestS3ConfigFromEnv(t *testing.T) {
	t.Setenv("PDCP_SCAN_LOG_S3_BUCKET", "  acme-logs  ")
	t.Setenv("PDCP_SCAN_LOG_S3_REGION", "us-west-2")
	t.Setenv("PDCP_SCAN_LOG_S3_ACCESS_KEY_ID", "AKIA")
	t.Setenv("PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY", "shh")
	t.Setenv("PDCP_SCAN_LOG_S3_USE_PATH_STYLE", "true")
	t.Setenv("PDCP_SCAN_LOG_S3_PREFIX", "/logs/")

	cfg := S3ConfigFromEnv()
	if cfg.Bucket != "acme-logs" {
		t.Errorf("Bucket = %q, want the value trimmed", cfg.Bucket)
	}
	if cfg.Prefix != "logs" {
		t.Errorf("Prefix = %q, want slashes trimmed so keys never double up", cfg.Prefix)
	}
	if !cfg.UsePathStyle {
		t.Error("UsePathStyle = false, want true")
	}
	if !cfg.Enabled() {
		t.Error("Enabled() = false with a bucket set")
	}
}

func TestS3ConfigDefaultPrefix(t *testing.T) {
	t.Setenv("PDCP_SCAN_LOG_S3_BUCKET", "acme-logs")
	if got := S3ConfigFromEnv().Prefix; got != "scan-logs" {
		t.Errorf("Prefix = %q, want the scan-logs default", got)
	}
}

func TestS3ConfigValidate(t *testing.T) {
	valid := S3Config{Bucket: "b", Region: "us-east-1", AccessKeyID: "k", SecretKey: "s"}

	tests := []struct {
		name    string
		cfg     S3Config
		wantErr string
	}{
		{"disabled is always valid", S3Config{}, ""},
		{"fully configured", valid, ""},
		{"with endpoint", withEndpoint(valid, "https://minio.internal:9000"), ""},
		{"no region", without(valid, func(c *S3Config) { c.Region = "" }), "PDCP_SCAN_LOG_S3_REGION"},
		{"no access key", without(valid, func(c *S3Config) { c.AccessKeyID = "" }), "PDCP_SCAN_LOG_S3_ACCESS_KEY_ID"},
		{"no secret", without(valid, func(c *S3Config) { c.SecretKey = "" }), "PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY"},
		{"blank region", without(valid, func(c *S3Config) { c.Region = "   " }), "PDCP_SCAN_LOG_S3_REGION"},
		{"bucket is a url", without(valid, func(c *S3Config) { c.Bucket = "s3://b/x" }), "must be a bucket name"},
		{"endpoint without scheme", withEndpoint(valid, "minio:9000"), "must start with http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error naming %s", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %q, want it to name %s", err, tt.wantErr)
			}
		})
	}
}

func without(c S3Config, mutate func(*S3Config)) S3Config {
	mutate(&c)
	return c
}

func withEndpoint(c S3Config, endpoint string) S3Config {
	c.Endpoint = endpoint
	return c
}

func TestValidateS3ConfigReadsEnv(t *testing.T) {
	t.Setenv("PDCP_SCAN_LOG_S3_BUCKET", "acme-logs")
	t.Setenv("PDCP_SCAN_LOG_S3_REGION", "")
	t.Setenv("PDCP_SCAN_LOG_S3_ACCESS_KEY_ID", "")
	t.Setenv("PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY", "")

	if err := ValidateS3Config(); err == nil {
		t.Fatal("ValidateS3Config() = nil, want the missing region reported")
	}
}

func TestS3UploadedObjectGunzips(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)

	content := strings.Repeat(`{"template":"cve","host":"example.com"}`+"\n", 500)
	if err := Upload(context.Background(), []Uploader{NewS3Uploader(store.config())},
		testMeta(), writeOutput(t, content)); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	req := store.requests()[0]
	if int64(len(req.body)) >= int64(len(content)) {
		t.Errorf("uploaded %d bytes for %d of JSONL, want it compressed", len(req.body), len(content))
	}
	if got := gunzip(t, req.body); got != content {
		t.Error("uploaded object does not gunzip back to the original output")
	}
}

func TestS3UploaderSkipsEmptyOutput(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)
	empty := filepath.Join(t.TempDir(), "chunk.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Upload(context.Background(), []Uploader{NewS3Uploader(store.config())}, testMeta(), empty); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if n := len(store.requests()); n != 0 {
		t.Errorf("%d requests for an empty output, want 0", n)
	}
}

// A proxy URL routinely carries basic-auth, url.Parse errors embed the raw
// URL, and every slog line here is persisted into the debug DB the agent
// uploads to the platform.
func TestProxyParseFailureDoesNotLogCredentials(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	t.Setenv("PROXY_URL", "http://user:sup3rsecret@bad host:8080")
	_ = proxyAwareHTTPClient()

	logged := buf.String()
	if !strings.Contains(logged, "ignoring unparseable proxy") {
		t.Fatalf("expected the warning, got %q", logged)
	}
	for _, leak := range []string{"sup3rsecret", "user:"} {
		if strings.Contains(logged, leak) {
			t.Errorf("log line leaks %q: %s", leak, logged)
		}
	}
}

// PROXY_URL plus a private endpoint is a documented combination, so NO_PROXY
// has to be honoured or in-cluster MinIO is unreachable through the proxy.
func TestProxyHonoursNoProxy(t *testing.T) {
	t.Setenv("PROXY_URL", "http://corp-proxy:3128")
	t.Setenv("NO_PROXY", "minio,127.0.0.1")

	transport := proxyAwareHTTPClient().Transport.(*http.Transport)

	proxied, err := transport.Proxy(&http.Request{URL: mustParse(t, "http://s3.amazonaws.com/b/k")})
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if proxied == nil || proxied.Host != "corp-proxy:3128" {
		t.Errorf("external host proxy = %v, want corp-proxy:3128", proxied)
	}

	direct, err := transport.Proxy(&http.Request{URL: mustParse(t, "http://minio:9000/b/k")})
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if direct != nil {
		t.Errorf("NO_PROXY host proxy = %v, want direct", direct)
	}
}

// With PROXY_URL unset the cloned DefaultTransport keeps
// http.ProxyFromEnvironment, so ambient HTTP_PROXY/HTTPS_PROXY still apply.
func TestProxyUnsetKeepsAmbientProxyAndTimeout(t *testing.T) {
	t.Setenv("PROXY_URL", "")
	transport := proxyAwareHTTPClient().Transport.(*http.Transport)

	if transport.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, responseHeaderTimeout)
	}
	if transport.Proxy == nil {
		t.Error("Proxy = nil, want the ambient environment proxy preserved")
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// The SDK reads an error body unbounded and puts it in the message, and the
// message reaches a log line that is written into the uploaded debug DB.
func TestS3UploaderTruncatesHugeBackendError(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")

	huge := strings.Repeat("A", 200_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 403 rather than 500: a retryable status would spend the test in
		// SDK backoff before the message is ever surfaced.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><Code>AccessDenied</Code><Message>" + huge + "</Message></Error>"))
	}))
	t.Cleanup(srv.Close)

	cfg := S3Config{Bucket: "b", Region: "us-east-1", AccessKeyID: "k", SecretKey: "s",
		Endpoint: srv.URL, UsePathStyle: true}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := NewS3Uploader(cfg).Upload(ctx, testMeta(), writeOutput(t, "line\n"), 5)
	if err == nil {
		t.Fatal("Upload() = nil, want the 500 reported")
	}
	if len(err.Error()) > maxErrorMessageBytes+len("put object: ")+len("... (truncated)") {
		t.Errorf("error is %d bytes, want it truncated near %d", len(err.Error()), maxErrorMessageBytes)
	}
}

// Redaction must not cost the error chain: a caller has to be able to tell a
// permanent policy failure from a transient one.
func TestS3UploaderErrorRemainsInspectable(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`))
	}))
	t.Cleanup(srv.Close)

	cfg := S3Config{Bucket: "b", Region: "us-east-1", AccessKeyID: "k", SecretKey: "s",
		Endpoint: srv.URL, UsePathStyle: true}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := NewS3Uploader(cfg).Upload(ctx, testMeta(), writeOutput(t, "line\n"), 5)
	if err == nil {
		t.Fatal("Upload() = nil, want the 403 reported")
	}

	var apiErr interface{ ErrorCode() string }
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As found no API error in %v; the chain was flattened", err)
	}
	if apiErr.ErrorCode() != "AccessDenied" {
		t.Errorf("ErrorCode() = %q, want AccessDenied", apiErr.ErrorCode())
	}
}

func TestS3UploaderRejectsOversizeObject(t *testing.T) {
	resetS3ClientCache(t)
	t.Setenv("PROXY_URL", "")
	store := newS3Store(t)

	_, err := NewS3Uploader(store.config()).Upload(
		context.Background(), testMeta(), writeOutput(t, "line\n"), maxS3ObjectBytes+1)
	if err == nil {
		t.Fatal("Upload() = nil, want the size limit enforced before the body is sent")
	}
	if n := len(store.requests()); n != 0 {
		t.Errorf("%d requests for an oversize object, want it rejected before the PUT", n)
	}
}

// A platform-generated id with a dot or over 50 characters is legitimate and
// must not be rejected; validate.Name would have refused both.
func TestS3ObjectKeyAcceptsRealisticIDs(t *testing.T) {
	u := NewS3Uploader(S3Config{Bucket: "b", Prefix: "scan-logs"})

	tests := []struct {
		name string
		meta Meta
		want string
	}{
		{"xid", Meta{ScanID: "d35h1tee67qc73c71olg", ChunkID: "d35h1tf67qc73c71olh", HistoryID: 7},
			"scan-logs/d35h1tee67qc73c71olg/7/d35h1tf67qc73c71olh.jsonl.gz"},
		{"uuid", Meta{ScanID: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", ChunkID: "c1", HistoryID: 1},
			"scan-logs/3f2504e0-4f89-11d3-9a0c-0305e82c3301/1/c1.jsonl.gz"},
		{"dotted composite", Meta{ScanID: "scan-abc.1", ChunkID: "chunk.2", HistoryID: 3},
			"scan-logs/scan-abc.1/3/chunk.2.jsonl.gz"},
		{"over 50 chars", Meta{ScanID: strings.Repeat("a", 64), ChunkID: "c", HistoryID: 1},
			"scan-logs/" + strings.Repeat("a", 64) + "/1/c.jsonl.gz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.objectKey(tt.meta)
			if err != nil {
				t.Fatalf("objectKey: %v", err)
			}
			if got != tt.want {
				t.Errorf("objectKey = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestS3ConfigRejectsTraversalPrefix(t *testing.T) {
	base := S3Config{Bucket: "b", Region: "us-east-1", AccessKeyID: "k", SecretKey: "s"}
	for _, prefix := range []string{"../../../other-tenant", "a/../../b", "a/./b", "bad\x00seg"} {
		cfg := base
		cfg.Prefix = prefix
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate() = nil for prefix %q, want it rejected", prefix)
		}
	}
}

// envutil silently falls back to the default on an unparseable bool, so
// path-style would read as false and every MinIO upload would fail on a
// hostname that does not resolve.
func TestS3ConfigRejectsUnparseablePathStyle(t *testing.T) {
	t.Setenv("PDCP_SCAN_LOG_S3_BUCKET", "acme-logs")
	t.Setenv("PDCP_SCAN_LOG_S3_REGION", "us-east-1")
	t.Setenv("PDCP_SCAN_LOG_S3_ACCESS_KEY_ID", "k")
	t.Setenv("PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY", "s")
	t.Setenv("PDCP_SCAN_LOG_S3_USE_PATH_STYLE", "true ")

	err := ValidateS3Config()
	if err == nil {
		t.Fatal("ValidateS3Config() = nil, want the unparseable bool reported")
	}
	if !strings.Contains(err.Error(), "PDCP_SCAN_LOG_S3_USE_PATH_STYLE") {
		t.Errorf("error = %q, want it to name the variable", err)
	}
}

// A secret from a k8s secretRef built with --from-file keeps a trailing
// newline. Signing with it fails every request, and the boot validator would
// have passed it.
func TestS3ConfigTrimsCredentials(t *testing.T) {
	t.Setenv("PDCP_SCAN_LOG_S3_BUCKET", "acme-logs")
	t.Setenv("PDCP_SCAN_LOG_S3_REGION", "us-east-1")
	t.Setenv("PDCP_SCAN_LOG_S3_ACCESS_KEY_ID", "AKIA\n")
	t.Setenv("PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY", "shh\n")

	cfg := S3ConfigFromEnv()
	if cfg.AccessKeyID != "AKIA" || cfg.SecretKey != "shh" {
		t.Errorf("credentials not trimmed: id=%q secret=%q", cfg.AccessKeyID, cfg.SecretKey)
	}
}

func TestPlaintextWarning(t *testing.T) {
	tests := []struct {
		endpoint string
		want     bool
	}{
		{"", false},
		{"https://s3.amazonaws.com", false},
		{"http://127.0.0.1:9000", false},
		{"http://localhost:9000", false},
		{"http://minio:9000", true},
		{"http://10.0.0.5:9000", true},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			got := S3Config{Endpoint: tt.endpoint}.PlaintextWarning() != ""
			if got != tt.want {
				t.Errorf("PlaintextWarning() non-empty = %v, want %v", got, tt.want)
			}
		})
	}
}
