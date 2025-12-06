package types

import (
	"encoding/json"
	"time"
)

// ScanLogUploadEntry represents a single scan log entry to upload
type ScanLogUploadEntry struct {
	// Required fields
	HistoryID   int64  `json:"history_id"`
	Matched     bool   `json:"matched"`
	RescanCount int64  `json:"rescan_count"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	TemplateID  string `json:"template_id"`
	Timestamp   string `json:"timestamp"` // RFC3339 format date-time

	// Optional fields
	Error       *string `json:"error,omitempty"`
	Event       *string `json:"event,omitempty"`       // Raw nuclei event JSON payload
	LogSeverity *string `json:"log_severity,omitempty"` // enum: critical, error, warning, info, debug
	VulnHash    *string `json:"vuln_hash,omitempty"`
}

// ScanLogUploadRequest is an array of scan log entries
type ScanLogUploadRequest []ScanLogUploadEntry

// ScanLogUploadResponse represents the response from the upload endpoint
type ScanLogUploadResponse struct {
	Status string `json:"status"`
}

// Validate checks if the entry has all required fields populated
func (e *ScanLogUploadEntry) Validate() error {
	if e.HistoryID == 0 {
		return &ValidationError{Field: "history_id", Message: "history_id is required"}
	}
	if e.Target == "" {
		return &ValidationError{Field: "target", Message: "target is required"}
	}
	if e.TemplateID == "" {
		return &ValidationError{Field: "template_id", Message: "template_id is required"}
	}
	if e.Severity == "" {
		return &ValidationError{Field: "severity", Message: "severity is required"}
	}
	if e.Timestamp == "" {
		return &ValidationError{Field: "timestamp", Message: "timestamp is required"}
	}
	return nil
}

// SetTimestamp sets the timestamp from a time.Time value
func (e *ScanLogUploadEntry) SetTimestamp(t time.Time) {
	e.Timestamp = t.Format(time.RFC3339)
}

// SetError sets the error field
func (e *ScanLogUploadEntry) SetError(err string) {
	e.Error = &err
}

// SetEvent sets the event field with raw JSON
func (e *ScanLogUploadEntry) SetEvent(event interface{}) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}
	eventStr := string(eventJSON)
	e.Event = &eventStr
	return nil
}

// SetLogSeverity sets the log severity field
func (e *ScanLogUploadEntry) SetLogSeverity(severity string) {
	// Validate enum values
	validSeverities := map[string]bool{
		"critical": true,
		"error":    true,
		"warning":  true,
		"info":     true,
		"debug":    true,
	}
	if validSeverities[severity] {
		e.LogSeverity = &severity
	}
}

// SetVulnHash sets the vulnerability hash field
func (e *ScanLogUploadEntry) SetVulnHash(hash string) {
	e.VulnHash = &hash
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

