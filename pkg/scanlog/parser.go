package scanlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"log/slog"

	"github.com/dustin/go-humanize"
	"github.com/projectdiscovery/pd-agent/pkg/types"
)

// ParseNucleiOutput parses nuclei JSON output (one JSON object per line)
func ParseNucleiOutput(output string) ([]types.ScanLogUploadEntry, error) {
	var entries []types.ScanLogUploadEntry
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Increase buffer size to handle large JSON lines (default is 64KB, increase to 10MB)
	const maxCapacityStr = "10MB"
	maxCapacity, err := humanize.ParseBytes(maxCapacityStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse buffer size %s: %w", maxCapacityStr, err)
	}
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, int(maxCapacity))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// Skip non-JSON lines (might be log messages)
			continue
		}

		// Create a default scan context (will be overridden by caller if needed)
		scanContext := NewScanContext("")
		entry, err := BuildLogEntry(event, scanContext)
		if err != nil {
			// Log but continue processing other entries
			continue
		}

		entries = append(entries, *entry)
	}

	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("error scanning output: %w", err)
	}

	return entries, nil
}

// ParseOutputFile reads and parses JSON lines from a nuclei output file
func ParseOutputFile(outputFilePath, scanID string) ([]types.ScanLogUploadEntry, error) {
	if outputFilePath == "" {
		return nil, nil // No output file, return empty
	}

	// Check if file exists
	if _, err := os.Stat(outputFilePath); os.IsNotExist(err) {
		return nil, nil // File doesn't exist, return empty (not an error)
	}

	// Read file content
	content, err := os.ReadFile(outputFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading output file %s: %w", outputFilePath, err)
	}

	// Parse JSON lines (same as ParseNucleiOutput)
	return ParseNucleiOutput(string(content))
}

// ExtractLogEntries extracts log entries from output file ONLY (no fallback to stdout/stderr for log upload)
func ExtractLogEntries(taskResult *types.TaskResult, scanID string, outputFilePath string) ([]types.ScanLogUploadEntry, error) {
	var allEntries []types.ScanLogUploadEntry

	// Create scan context
	scanContext := NewScanContext(scanID)

	// Parse output file ONLY (no fallback to stdout/stderr for log upload)
	if outputFilePath != "" {
		fileEntries, err := ParseOutputFile(outputFilePath, scanID)
		if err != nil {
			// Log error and return empty entries (don't fallback to stdout)
			slog.Warn("Failed to parse output file for log upload", "file", outputFilePath, "error", err)
			return nil, fmt.Errorf("error parsing output file: %w", err)
		}

		// Update scan context for all entries
		for i := range fileEntries {
			fileEntries[i].HistoryID = scanContext.HistoryID
			fileEntries[i].RescanCount = scanContext.RescanCount
		}
		allEntries = append(allEntries, fileEntries...)
	} else {
		// No output file - return empty (log upload requires output file)
		slog.Debug("No output file provided for log upload", "scan_id", scanID)
		return []types.ScanLogUploadEntry{}, nil
	}

	// Note: stdout and stderr are still collected in taskResult for other purposes
	// but are NOT used for log upload parsing

	return allEntries, nil
}
