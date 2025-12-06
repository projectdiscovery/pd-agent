package scanlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg"
	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	envutil "github.com/projectdiscovery/utils/env"
)

var (
	// PDCPApiKey is the API key for authentication
	PDCPApiKey = envutil.GetEnvOrDefault("PDCP_API_KEY", "")
	// TeamIDEnv is the team ID for authentication
	TeamIDEnv = envutil.GetEnvOrDefault("PDCP_TEAM_ID", "")
)

// UploadScanLogs uploads scan log entries to the API
func UploadScanLogs(ctx context.Context, scanID, teamID string, entries []types.ScanLogUploadEntry) (*types.ScanLogUploadResponse, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries to upload")
	}

	// Validate entries
	for i := range entries {
		if err := entries[i].Validate(); err != nil {
			return nil, fmt.Errorf("entry %d validation failed: %w", i, err)
		}
	}

	// Build request payload
	requestBody := types.ScanLogUploadRequest(entries)
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %w", err)
	}

	// Build API URL
	apiURL := fmt.Sprintf("%s/v1/scans/%s/scan_log/upload", pkg.PCDPApiServer, scanID)

	// Create authenticated client
	httpClient, err := client.CreateAuthenticatedClient(teamID, PDCPApiKey)
	if err != nil {
		return nil, fmt.Errorf("error creating authenticated client: %w", err)
	}

	// Perform request with retry logic
	maxRetries := 5
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Create request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
		if err != nil {
			lastErr = fmt.Errorf("error creating request: %w", err)
			if attempt < maxRetries {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return nil, lastErr
		}

		// Set content type
		req.Header.Set("Content-Type", "application/json")

		// Execute request
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("error sending request: %w", err)
			if attempt < maxRetries {
				slog.Warn("error sending scan log upload request, retrying",
					"attempt", attempt,
					"max_retries", maxRetries,
					"scan_id", scanID,
					"entry_count", len(entries),
					"error", err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return nil, lastErr
		}

		// Read response
		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("error reading response: %w", err)
			if attempt < maxRetries {
				slog.Warn("error reading scan log upload response, retrying",
					"attempt", attempt,
					"max_retries", maxRetries,
					"scan_id", scanID,
					"error", err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return nil, lastErr
		}

		// Check status code
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
			if attempt < maxRetries {
				slog.Warn("scan log upload returned non-OK status, retrying",
					"attempt", attempt,
					"max_retries", maxRetries,
					"scan_id", scanID,
					"status_code", resp.StatusCode,
					"body", string(respBody))
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return nil, lastErr
		}

		// Parse response
		var response types.ScanLogUploadResponse
		if err := json.Unmarshal(respBody, &response); err != nil {
			return nil, fmt.Errorf("error unmarshaling response: %w", err)
		}

		// Success
		slog.Debug("Successfully uploaded scan logs",
			"scan_id", scanID,
			"entry_count", len(entries),
			"status", response.Status)
		return &response, nil
	}

	return nil, fmt.Errorf("upload failed after %d attempts: %w", maxRetries, lastErr)
}

