package scanlog

import "time"

// ScanContext contains metadata about the scan execution
type ScanContext struct {
	ScanID      string
	HistoryID   int64
	RescanCount int64
	StartTime   time.Time
}

// NewScanContext creates a new scan context with default values
func NewScanContext(scanID string) *ScanContext {
	return &ScanContext{
		ScanID:      scanID,
		HistoryID:   1, // Default to 1, can be overridden
		RescanCount: 0, // Default to 0, can be overridden
		StartTime:   time.Now(),
	}
}

