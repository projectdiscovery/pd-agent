package agentdb

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	defaultTruncateInterval = 30 * time.Second
	// bytesPerLogRow is the estimated average size of a log row in bytes.
	bytesPerLogRow = 200
	// bytesPerMetricRow is the estimated average size of a metric row in bytes.
	bytesPerMetricRow = 150
	// retainPercent is the percentage of maxRows to keep after truncation.
	// Keeping 80% avoids re-triggering on the very next cycle.
	retainPercent = 80
	// vacuumPages is the number of free pages to reclaim per cycle.
	vacuumPages = 200
	// maxTaskRows is the cap for the tasks table; only non-running rows count.
	maxTaskRows = 10000
)

// Truncator runs a periodic maintenance loop that enforces table size caps
// by deleting oldest rows and reclaiming disk space via incremental vacuum.
type Truncator struct {
	store      *SQLiteStore
	maxLogRows int64
	maxMetRows int64
	interval   time.Duration
}

// NewTruncator creates a truncator with byte-based caps.
// Internally converts to row limits: logCapBytes/200, metCapBytes/150.
func NewTruncator(store *SQLiteStore, logCapBytes, metCapBytes int64) *Truncator {
	return &Truncator{
		store:      store,
		maxLogRows: logCapBytes / bytesPerLogRow,
		maxMetRows: metCapBytes / bytesPerMetricRow,
		interval:   defaultTruncateInterval,
	}
}

// Run blocks until ctx is cancelled, running truncation every interval.
func (t *Truncator) Run(ctx context.Context) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	// Run once immediately on start so callers don't wait a full interval.
	if err := t.truncateOnce(); err != nil {
		slog.Warn("truncator: initial pass failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := t.truncateOnce(); err != nil {
				slog.Warn("truncator: pass failed", "error", err)
			}
		}
	}
}

// truncateOnce performs a single truncation pass:
// 1. Delete oldest log rows if count exceeds cap (retain 80%).
// 2. Delete oldest metric rows if count exceeds cap (retain 80%).
// 3. Reclaim free pages via incremental vacuum.
func (t *Truncator) truncateOnce() error {
	if err := t.truncateTable("logs", t.maxLogRows); err != nil {
		return fmt.Errorf("truncate logs: %w", err)
	}
	if err := t.truncateTable("metrics", t.maxMetRows); err != nil {
		return fmt.Errorf("truncate metrics: %w", err)
	}
	// Cap tasks at maxTaskRows; only non-running rows are counted/deleted so
	// long-running scans don't get evicted and don't push out completed history.
	if err := t.truncateTasks(maxTaskRows); err != nil {
		return fmt.Errorf("truncate tasks: %w", err)
	}
	if _, err := t.store.db.Exec(fmt.Sprintf("PRAGMA incremental_vacuum(%d)", vacuumPages)); err != nil {
		return fmt.Errorf("incremental_vacuum: %w", err)
	}

	// Refresh updated_at so the DB can be used for liveness detection.
	_, _ = t.store.db.Exec("UPDATE agent_info SET updated_at = ? WHERE id = 1",
		time.Now().UTC().Format(time.RFC3339Nano))

	return nil
}

// truncateTable deletes the oldest rows from table if count exceeds maxRows,
// keeping retainPercent of maxRows.
func (t *Truncator) truncateTable(table string, maxRows int64) error {
	if table != "logs" && table != "metrics" {
		return fmt.Errorf("invalid table: %q", table)
	}
	if maxRows <= 0 {
		return nil
	}

	var count int64
	if err := t.store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		return fmt.Errorf("count %s: %w", table, err)
	}

	if count <= maxRows {
		return nil
	}

	retain := maxRows * retainPercent / 100
	deleteCount := count - retain

	q := fmt.Sprintf("DELETE FROM %s WHERE id IN (SELECT id FROM %s ORDER BY id ASC LIMIT ?)", table, table)
	if _, err := t.store.db.Exec(q, deleteCount); err != nil {
		return fmt.Errorf("delete from %s: %w", table, err)
	}

	return nil
}

// truncateTasks deletes the oldest non-running task rows when the count of
// non-running rows exceeds maxRows. Running tasks are never evicted.
func (t *Truncator) truncateTasks(maxRows int64) error {
	if maxRows <= 0 {
		return nil
	}

	var count int64
	if err := t.store.db.QueryRow("SELECT COUNT(*) FROM tasks WHERE status != 'running'").Scan(&count); err != nil {
		return fmt.Errorf("count tasks: %w", err)
	}

	if count <= maxRows {
		return nil
	}

	retain := maxRows * retainPercent / 100
	deleteCount := count - retain

	q := "DELETE FROM tasks WHERE status != 'running' AND id IN (SELECT id FROM tasks WHERE status != 'running' ORDER BY id ASC LIMIT ?)"
	if _, err := t.store.db.Exec(q, deleteCount); err != nil {
		return fmt.Errorf("delete from tasks: %w", err)
	}

	return nil
}
