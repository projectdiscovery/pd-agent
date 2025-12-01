package scanlog

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/types"
	"github.com/projectdiscovery/utils/batcher"
	envutil "github.com/projectdiscovery/utils/env"
)

var (
	// Default batch size for log uploads
	DefaultBatchSize = 1000
	// Default flush interval for log uploads
	DefaultFlushInterval = 30 * time.Second
)

// GetBatchSize returns the batch size from environment or default
func GetBatchSize() int {
	envVal := envutil.GetEnvOrDefault("PDCP_SCAN_LOG_BATCH_SIZE", "")
	if envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size > 0 {
			return size
		}
	}
	return DefaultBatchSize
}

// GetFlushInterval returns the flush interval from environment or default
func GetFlushInterval() time.Duration {
	envVal := envutil.GetEnvOrDefault("PDCP_SCAN_LOG_FLUSH_INTERVAL", "")
	if envVal != "" {
		if interval, err := strconv.Atoi(envVal); err == nil && interval > 0 {
			return time.Duration(interval) * time.Second
		}
	}
	return DefaultFlushInterval
}

// IsLogUploadEnabled returns whether log upload is enabled
func IsLogUploadEnabled() bool {
	return envutil.GetEnvOrDefault("PDCP_ENABLE_SCAN_LOG_UPLOAD", "true") == "true"
}

// NewScanLogBatcher creates a new batcher for scan log entries
func NewScanLogBatcher(scanID, teamID string) *batcher.Batcher[types.ScanLogUploadEntry] {
	batchSize := GetBatchSize()
	flushInterval := GetFlushInterval()

	b := batcher.New(
		batcher.WithMaxCapacity[types.ScanLogUploadEntry](batchSize),
		batcher.WithFlushInterval[types.ScanLogUploadEntry](flushInterval),
		batcher.WithFlushCallback[types.ScanLogUploadEntry](func(entries []types.ScanLogUploadEntry) {
			// Upload entries in background (non-blocking)
			go func() {
				ctx := context.Background()
				if _, err := UploadScanLogs(ctx, scanID, teamID, entries); err != nil {
					slog.Error("Failed to upload scan logs",
						"scan_id", scanID,
						"entry_count", len(entries),
						"error", err)
				} else {
					slog.Debug("Uploaded scan logs",
						"scan_id", scanID,
						"entry_count", len(entries))
				}
			}()
		}),
	)

	// Start the batcher
	go b.Run()

	return b
}

