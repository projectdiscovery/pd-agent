package scanlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// signedUploadResponse mirrors /v1/scans/{scan_id}/scan_log/upload-url.
// Headers are authoritative: set them verbatim on the PUT and add nothing
// else, since the SigV4 signature covers headers.
type signedUploadResponse struct {
	UploadURL  string            `json:"upload_url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	MaxBytes   int64             `json:"max_bytes"`
	ObjectPath string            `json:"object_path"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

// PlatformUploader stores scan logs in ProjectDiscovery-managed storage.
type PlatformUploader struct{}

// NewPlatformUploader returns an uploader targeting PDCP-managed storage.
func NewPlatformUploader() *PlatformUploader { return &PlatformUploader{} }

// Name identifies the destination in logs.
func (*PlatformUploader) Name() string { return "pdcp" }

// Upload ships the gzipped scan log via:
//  1. POST /v1/scans/{scan_id}/scan_log/upload-url?history_id=N with {"filename": ...}
//  2. PUT the bytes to the signed URL with the response Headers verbatim.
//
// The payload is an opaque .gz blob (no Content-Encoding) so the SigV4 signed
// headers never need to cover Content-Encoding; server gunzips on read.
func (*PlatformUploader) Upload(ctx context.Context, m Meta, gzPath string, gzSize int64) (string, error) {
	filename := m.ChunkID + ".jsonl.gz"
	httpClient, err := client.CreateAuthenticatedClient(m.TeamID, envconfig.APIKey())
	if err != nil {
		return "", fmt.Errorf("auth client: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]string{"filename": filename})
	apiURL := fmt.Sprintf("%s/v1/scans/%s/scan_log/upload-url?history_id=%d",
		envconfig.APIServer(), m.ScanID, m.HistoryID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("build upload-url request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get upload-url: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upload-url status %d: %s", resp.StatusCode, string(respBody))
	}

	var signed signedUploadResponse
	if err := json.Unmarshal(respBody, &signed); err != nil {
		return "", fmt.Errorf("decode upload-url response: %w", err)
	}
	if signed.UploadURL == "" || signed.Method == "" {
		return "", fmt.Errorf("upload-url response missing url/method")
	}
	if signed.MaxBytes > 0 && gzSize > signed.MaxBytes {
		return "", fmt.Errorf("gzipped output %d bytes exceeds signed-url max %d", gzSize, signed.MaxBytes)
	}

	f, err := os.Open(gzPath)
	if err != nil {
		return "", fmt.Errorf("open gz: %w", err)
	}
	defer func() { _ = f.Close() }()

	putReq, err := http.NewRequestWithContext(ctx, signed.Method, signed.UploadURL, f)
	if err != nil {
		return "", fmt.Errorf("build PUT: %s", stripSignedURL(err))
	}
	putReq.ContentLength = gzSize
	for k, v := range signed.Headers {
		putReq.Header.Set(k, v)
	}

	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		return "", fmt.Errorf("PUT: %s", stripSignedURL(err))
	}
	defer func() { _ = putResp.Body.Close() }()

	if putResp.StatusCode != http.StatusOK && putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putResp.Body)
		return "", fmt.Errorf("PUT status %d: %s", putResp.StatusCode, string(body))
	}
	_, _ = io.Copy(io.Discard, putResp.Body)

	return signed.ObjectPath, nil
}

// stripSignedURL drops the URL from a *url.Error so SigV4/GCS HMAC query
// signatures never reach the logs. Keeps operation and underlying cause.
func stripSignedURL(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Sprintf("%s: %s", ue.Op, ue.Err)
	}
	return err.Error()
}
