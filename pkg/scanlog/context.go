package scanlog

import (
	"log/slog"
	"strconv"
	"time"
)

// ScanContext contains metadata about the scan execution
type ScanContext struct {
	ScanID      string
	HistoryID   int64
	RescanCount int64
	StartTime   time.Time
}

// NewScanContext creates a new scan context. historyID arrives as a string
// from the work message (json field history_id); we parse it to int64 here
// because ScanLogUploadEntry.HistoryID is int64 on the wire. Empty or
// unparseable historyID falls back to 1 — same default the package used
// before this field was wired through.
func NewScanContext(scanID, historyID string) *ScanContext {
	hid := int64(1)
	if historyID != "" {
		parsed, err := strconv.ParseInt(historyID, 10, 64)
		if err != nil {
			slog.Warn("scanlog: history_id is not parseable as int64; defaulting to 1",
				"scan_id", scanID, "history_id", historyID, "error", err)
		} else {
			hid = parsed
		}
	}
	return &ScanContext{
		ScanID:      scanID,
		HistoryID:   hid,
		RescanCount: 0, // Default to 0, can be overridden
		StartTime:   time.Now(),
	}
}
