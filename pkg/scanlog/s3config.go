package scanlog

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// maxS3ObjectBytes bounds one gzipped chunk log. Well under S3's 5GiB
// single-PutObject ceiling, because that ceiling only catches a request the
// API would reject and lets a runaway scan burn egress and customer storage
// first. Real chunk logs measure tens of MiB, and at the compression this
// data shows 512MiB gzipped is already several GiB of JSONL for one chunk,
// which means something went wrong rather than something got big.
const maxS3ObjectBytes int64 = 512 << 20

// S3Config describes a customer-owned S3 destination. Credentials are always
// explicit: the AWS default chain is deliberately not consulted, so no ambient
// credential on the host can be used to write to the operator's bucket.
type S3Config struct {
	Bucket       string
	Region       string
	AccessKeyID  string
	SecretKey    string
	Endpoint     string
	UsePathStyle bool
	Prefix       string
}

// S3ConfigFromEnv reads the destination config. Bucket empty means the
// destination is off.
//
// Every field is trimmed, credentials included: a secret sourced from a
// Kubernetes secretRef built with --from-file keeps its trailing newline, and
// SigV4 would sign with it and fail every request.
func S3ConfigFromEnv() S3Config {
	return S3Config{
		Bucket:       strings.TrimSpace(envconfig.ScanLogS3Bucket()),
		Region:       strings.TrimSpace(envconfig.ScanLogS3Region()),
		AccessKeyID:  strings.TrimSpace(envconfig.ScanLogS3AccessKeyID()),
		SecretKey:    strings.TrimSpace(envconfig.ScanLogS3SecretKey()),
		Endpoint:     strings.TrimSpace(envconfig.ScanLogS3Endpoint()),
		UsePathStyle: envconfig.ScanLogS3UsePathStyle(),
		Prefix:       strings.Trim(strings.TrimSpace(envconfig.ScanLogS3Prefix()), "/"),
	}
}

// Enabled reports whether a bucket was named.
func (c S3Config) Enabled() bool { return c.Bucket != "" }

// Validate rejects a partial or malformed config so a typo stops the agent at
// boot. Anything that slips through here fails at upload time instead, where
// the only symptom is a per-chunk warning and a scan that still reports green.
func (c S3Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	for _, required := range []struct {
		key   string
		value string
	}{
		{envconfig.KeyScanLogS3Region, c.Region},
		{envconfig.KeyScanLogS3AccessKeyID, c.AccessKeyID},
		{envconfig.KeyScanLogS3SecretKey, c.SecretKey},
	} {
		// TrimSpace as well as empty: S3ConfigFromEnv already trims, but
		// Validate is exported and a hand-built config must not slip a
		// whitespace-only credential through into a signature.
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%s is required when %s is set",
				required.key, envconfig.KeyScanLogS3Bucket)
		}
	}
	if strings.ContainsAny(c.Bucket, `/\`) {
		return fmt.Errorf("%s must be a bucket name, not a path or URL", envconfig.KeyScanLogS3Bucket)
	}
	if c.Endpoint != "" && !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("%s must start with http:// or https://", envconfig.KeyScanLogS3Endpoint)
	}
	if err := validPrefix(c.Prefix); err != nil {
		return err
	}
	// Checked against the raw value: envutil falls back to the default on an
	// unparseable bool, so "true " would silently mean false, and path-style
	// off against MinIO fails every upload on a hostname that cannot resolve.
	return parseableBool(envconfig.KeyScanLogS3UsePathStyle)
}

// validPrefix keeps the prefix from walking out of its own key space. S3 keys
// are opaque, but path.Join resolves ".." and any backend that normalises the
// request path would resolve it too.
func validPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%s must not contain %q segments", envconfig.KeyScanLogS3Prefix, segment)
		}
	}
	for _, r := range prefix {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s must not contain control characters", envconfig.KeyScanLogS3Prefix)
		}
	}
	return nil
}

// parseableBool reports a boolean env var the agent would otherwise read as
// its default without saying so.
func parseableBool(key string) error {
	raw, set := os.LookupEnv(key)
	if !set || strings.TrimSpace(raw) == "" {
		return nil
	}
	if _, err := strconv.ParseBool(raw); err != nil {
		return fmt.Errorf("%s=%q is not a boolean (use true or false)", key, raw)
	}
	return nil
}

// ValidateS3Config checks the environment at boot.
func ValidateS3Config() error { return S3ConfigFromEnv().Validate() }

// PlaintextWarning describes the exposure when the endpoint is plaintext and
// not loopback. The scan log is every finding for the customer's hosts, and
// over http:// it travels in the clear along with a replayable Authorization
// header. In-cluster MinIO over http:// is a legitimate setup, so this warns
// rather than rejects.
func (c S3Config) PlaintextWarning() string {
	if !strings.HasPrefix(c.Endpoint, "http://") {
		return ""
	}
	host := strings.SplitN(strings.TrimPrefix(c.Endpoint, "http://"), "/", 2)[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" || net.ParseIP(host).IsLoopback() {
		return ""
	}
	return fmt.Sprintf("%s is plaintext http, scan logs and the signed request will cross the network unencrypted", envconfig.KeyScanLogS3Endpoint)
}
