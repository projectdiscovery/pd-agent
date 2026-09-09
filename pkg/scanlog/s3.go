package scanlog

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/net/http/httpproxy"

	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
	"github.com/projectdiscovery/pd-agent/pkg/validate"
)

// responseHeaderTimeout bounds a backend that completes the handshake and then
// says nothing. Deliberately not a whole-request timeout, which would kill a
// large upload part-way through a healthy transfer.
const responseHeaderTimeout = 60 * time.Second

// maxErrorMessageBytes truncates a backend's error text. The SDK reads the
// error body unbounded and puts it in the message, and every message reaches a
// log line that is persisted to the agent's debug DB.
const maxErrorMessageBytes = 2048

// S3Uploader writes scan logs to a customer-owned, S3-compatible bucket.
// Nothing about the object is reported back to the platform.
type S3Uploader struct {
	cfg S3Config
}

// NewS3Uploader returns an uploader for cfg. Validate the config at boot; this
// constructor assumes it already passed.
func NewS3Uploader(cfg S3Config) *S3Uploader { return &S3Uploader{cfg: cfg} }

// Name identifies the destination in logs.
func (*S3Uploader) Name() string { return "s3" }

var (
	s3ClientMu     sync.Mutex
	s3ClientCfg    S3Config
	s3ClientCached *s3.Client
)

// client returns a client for cfg, rebuilding only when the config changes.
// Destinations() runs once per chunk, so building a client per uploader would
// rebuild it for every chunk of every scan.
func (u *S3Uploader) client() *s3.Client {
	s3ClientMu.Lock()
	defer s3ClientMu.Unlock()

	if s3ClientCached != nil && s3ClientCfg == u.cfg {
		return s3ClientCached
	}

	opts := s3.Options{
		Region: u.cfg.Region,
		// Empty session token: only long-lived keys are supported. Temporary
		// credentials would expire with nothing here to refresh them.
		Credentials: credentials.NewStaticCredentialsProvider(
			u.cfg.AccessKeyID, u.cfg.SecretKey, ""),
		UsePathStyle: u.cfg.UsePathStyle,
		HTTPClient:   proxyAwareHTTPClient(),
		// Pinned, not fixing anything today: config.LoadDefaultConfig would
		// resolve this to WhenSupported, which sends x-amz-checksum-crc32 and
		// switches the body to aws-chunked with a trailer. Cloudflare R2 and
		// GCS interop reject both. Building Options directly leaves the field
		// Unset, which already means "no checksum" — this states the intent so
		// an SDK bump cannot quietly turn it on.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
	}
	// Left nil deliberately when unset: an endpoint derived from empty config
	// resolves to a hostname like https://.example.com and fails every request.
	if u.cfg.Endpoint != "" {
		opts.BaseEndpoint = aws.String(u.cfg.Endpoint)
	}

	s3ClientCfg, s3ClientCached = u.cfg, s3.New(opts)
	return s3ClientCached
}

// proxyAwareHTTPClient honours PROXY_URL so an agent on a restricted egress
// can reach the customer's bucket, and keeps TLS verification on: this talks
// to the customer's object store, not to an appliance with a private cert.
//
// PROXY_URL is fed through httpproxy rather than http.ProxyURL so that NO_PROXY
// still applies. Forcing every request through the proxy would break the
// documented in-cluster MinIO case, where the endpoint is not routable from it.
func proxyAwareHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseHeaderTimeout

	if raw := envconfig.ProxyURL(); raw != "" {
		if _, err := url.Parse(raw); err != nil {
			// stripSignedURL, because a url.Error carries the raw URL and a
			// proxy URL routinely carries basic-auth credentials. Every log
			// line here is persisted to the agent's uploaded debug DB.
			slog.Warn("scan-log: ignoring unparseable proxy for S3 uploads",
				"key", envconfig.KeyProxyURL, "error", stripSignedURL(err))
		} else {
			cfg := httpproxy.Config{
				HTTPProxy:  raw,
				HTTPSProxy: raw,
				NoProxy:    os.Getenv("NO_PROXY"),
			}
			proxyFunc := cfg.ProxyFunc()
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				return proxyFunc(req.URL)
			}
		}
	}
	return &http.Client{Transport: transport}
}

// redactedError keeps an error chain inspectable with errors.As while making
// sure the rendered text carries no signature and no unbounded backend body.
type redactedError struct {
	op   string
	text string
	err  error
}

func (e *redactedError) Error() string { return e.op + ": " + e.text }
func (e *redactedError) Unwrap() error { return e.err }

func redact(op string, err error) error {
	text := stripSignedURL(err)
	if len(text) > maxErrorMessageBytes {
		text = text[:maxErrorMessageBytes] + "... (truncated)"
	}
	return &redactedError{op: op, text: text, err: err}
}

// Upload PUTs the gzipped scan log at gzPath to the configured bucket and
// returns the s3:// location it landed at.
func (u *S3Uploader) Upload(ctx context.Context, m Meta, gzPath string, gzSize int64) (string, error) {
	key, err := u.objectKey(m)
	if err != nil {
		return "", err
	}
	if gzSize > maxS3ObjectBytes {
		return "", fmt.Errorf("gzipped output %d bytes exceeds the %d byte per-object limit", gzSize, maxS3ObjectBytes)
	}

	f, err := os.Open(gzPath)
	if err != nil {
		return "", fmt.Errorf("open gz: %w", err)
	}
	defer func() { _ = f.Close() }()

	// The *os.File is handed over unwrapped so the SDK can rewind it to retry.
	if _, err := u.client().PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(u.cfg.Bucket),
		Key:           aws.String(key),
		Body:          f,
		ContentLength: aws.Int64(gzSize),
		ContentType:   aws.String("application/gzip"),
	}); err != nil {
		return "", redact("put object", err)
	}

	return "s3://" + path.Join(u.cfg.Bucket, key), nil
}

// objectKey builds <prefix>/<scan_id>/<history_id>/<chunk_id>.jsonl.gz.
//
// The ids are re-checked because Upload is exported and reachable without
// going through scanlog.Upload. Validated because the agent does not generate
// them, not because a caller is assumed hostile: they arrive on the group
// stream and natsrpc rejects a malformed one at ingest.
func (u *S3Uploader) objectKey(m Meta) (string, error) {
	scanID, err := validate.PathSegment("scan_id", m.ScanID)
	if err != nil {
		return "", fmt.Errorf("refusing to build an object key: %w", err)
	}
	chunkID, err := validate.PathSegment("chunk_id", m.ChunkID)
	if err != nil {
		return "", fmt.Errorf("refusing to build an object key: %w", err)
	}

	segments := make([]string, 0, 4)
	if u.cfg.Prefix != "" {
		segments = append(segments, u.cfg.Prefix)
	}
	segments = append(segments, scanID, strconv.FormatInt(m.HistoryID, 10), chunkID+".jsonl.gz")
	return path.Join(segments...), nil
}
