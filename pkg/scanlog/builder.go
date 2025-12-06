package scanlog

import (
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/types"
)

// BuildLogEntry converts a nuclei event to a ScanLogUploadEntry
func BuildLogEntry(nucleiEvent map[string]interface{}, scanContext *ScanContext) (*types.ScanLogUploadEntry, error) {
	entry := &types.ScanLogUploadEntry{
		HistoryID:   scanContext.HistoryID,
		RescanCount: scanContext.RescanCount,
	}

	// Extract target (required)
	if target, ok := getString(nucleiEvent, "host", "matched-at", "url", "ip"); ok && target != "" {
		entry.Target = target
	} else {
		return nil, fmt.Errorf("target field not found in nuclei event")
	}

	// Extract template_id (required)
	if templateID, ok := getString(nucleiEvent, "template-id", "template", "template_id"); ok && templateID != "" {
		entry.TemplateID = templateID
	} else {
		// Try to extract from template path
		if templatePath, ok := getString(nucleiEvent, "template-path", "template_path"); ok {
			// Extract just the template name from path
			parts := strings.Split(templatePath, "/")
			if len(parts) > 0 {
				entry.TemplateID = parts[len(parts)-1]
			} else {
				entry.TemplateID = templatePath
			}
		} else {
			return nil, fmt.Errorf("template_id field not found in nuclei event")
		}
	}

	// Extract severity (required)
	if severity, ok := getString(nucleiEvent, "severity", "info", "level"); ok && severity != "" {
		entry.Severity = normalizeSeverity(severity)
	} else {
		// Default to info if not found
		entry.Severity = "info"
	}

	// Extract matched (required) - determine if this is a match or info event
	entry.Matched = isMatchEvent(nucleiEvent)

	// Extract timestamp (required)
	if timestamp, ok := getString(nucleiEvent, "timestamp", "time", "date"); ok && timestamp != "" {
		entry.Timestamp = timestamp
	} else {
		// Use current time if not found
		entry.SetTimestamp(time.Now())
	}

	// Extract optional fields
	if errMsg, ok := getString(nucleiEvent, "error", "err", "error-message"); ok && errMsg != "" {
		entry.SetError(errMsg)
	}

	// Store raw event JSON
	if err := entry.SetEvent(nucleiEvent); err != nil {
		// Log but don't fail
		_ = err
	}

	// Extract log severity
	if logLevel, ok := getString(nucleiEvent, "log-level", "log_level", "level"); ok {
		entry.SetLogSeverity(normalizeLogSeverity(logLevel))
	}

	// Extract vuln_hash
	if vulnHash, ok := getString(nucleiEvent, "vuln-hash", "vuln_hash", "hash"); ok && vulnHash != "" {
		entry.SetVulnHash(vulnHash)
	}

	return entry, nil
}

// getString extracts a string value from a map, trying multiple keys
func getString(m map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			switch v := val.(type) {
			case string:
				return v, true
			case interface{}:
				return fmt.Sprintf("%v", v), true
			}
		}
	}
	return "", false
}

// isMatchEvent determines if the event is a match (true) or info (false)
func isMatchEvent(event map[string]interface{}) bool {
	// Check for match indicators
	if matched, ok := event["matched"].(bool); ok {
		return matched
	}
	if eventType, ok := getString(event, "type", "event-type", "event_type"); ok {
		return strings.EqualFold(eventType, "match") || strings.EqualFold(eventType, "vulnerability")
	}
	// If it has severity and it's not info, consider it a match
	if severity, ok := getString(event, "severity"); ok {
		severity = strings.ToLower(severity)
		return severity != "info" && severity != ""
	}
	// Default to false (info event)
	return false
}

// normalizeSeverity normalizes nuclei severity to API format
func normalizeSeverity(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	// Map common nuclei severities
	severityMap := map[string]string{
		"critical": "critical",
		"high":     "high",
		"medium":   "medium",
		"low":      "low",
		"info":     "info",
		"unknown":  "info",
	}
	if mapped, ok := severityMap[severity]; ok {
		return mapped
	}
	// Return as-is if not in map
	return severity
}

// normalizeLogSeverity normalizes log level to API enum format
func normalizeLogSeverity(level string) string {
	level = strings.ToLower(strings.TrimSpace(level))
	validLevels := map[string]string{
		"critical": "critical",
		"error":    "error",
		"err":      "error",
		"warning":  "warning",
		"warn":     "warning",
		"info":     "info",
		"debug":    "debug",
	}
	if mapped, ok := validLevels[level]; ok {
		return mapped
	}
	// Default to info
	return "info"
}

