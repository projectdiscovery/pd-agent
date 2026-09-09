package scanlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestS3UploaderLive exercises the real SDK against a real S3-compatible
// server, which the httptest fake cannot prove: SigV4 against a real
// implementation, and whether the backend accepts the request shape at all.
// Opt-in, since it needs a reachable bucket and writes to it.
//
//	docker run -d --name minio -p 19000:9000 \
//	  -e MINIO_ROOT_USER=testkey -e MINIO_ROOT_PASSWORD=testsecret123 \
//	  quay.io/minio/minio:latest server /data
//	docker exec minio mc alias set local http://127.0.0.1:9000 testkey testsecret123
//	docker exec minio mc mb local/acme-logs
//
//	PD_TEST_S3_LIVE=1 \
//	PDCP_SCAN_LOG_S3_BUCKET=acme-logs \
//	PDCP_SCAN_LOG_S3_REGION=us-east-1 \
//	PDCP_SCAN_LOG_S3_ACCESS_KEY_ID=testkey \
//	PDCP_SCAN_LOG_S3_SECRET_ACCESS_KEY=testsecret123 \
//	PDCP_SCAN_LOG_S3_ENDPOINT=http://127.0.0.1:19000 \
//	PDCP_SCAN_LOG_S3_USE_PATH_STYLE=true \
//	go test ./pkg/scanlog/ -run Live -v
//
// Point the same variables at AWS or R2 to check those; region must be real on
// AWS, and "auto" only works on R2.
func TestS3UploaderLive(t *testing.T) {
	if os.Getenv("PD_TEST_S3_LIVE") != "1" {
		t.Skip("set PD_TEST_S3_LIVE=1 to run against a real bucket")
	}
	t.Setenv("PROXY_URL", "")
	resetS3ClientCache(t)

	cfg := S3ConfigFromEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	content := `{"template":"cve-2024-1","host":"example.com"}` + "\n"
	outputFile := filepath.Join(t.TempDir(), "chunk.jsonl")
	if err := os.WriteFile(outputFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	uploader := NewS3Uploader(cfg)
	if err := Upload(context.Background(), []Uploader{uploader}, testMeta(), outputFile); err != nil {
		t.Fatalf("Upload to %s: %v", cfg.Bucket, err)
	}

	key, err := uploader.objectKey(testMeta())
	if err != nil {
		t.Fatalf("objectKey: %v", err)
	}
	t.Logf("uploaded s3://%s/%s", cfg.Bucket, key)
}
