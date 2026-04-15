package agentdb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func insertTestLogs(t *testing.T, store *SQLiteStore, n int) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		entry := &LogEntry{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Line:      fmt.Sprintf("log-%d", i),
		}
		if err := store.InsertLog(ctx, entry); err != nil {
			t.Fatalf("InsertLog[%d]: %v", i, err)
		}
	}
}

func insertTestMetrics(t *testing.T, store *SQLiteStore, n int) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		sample := &MetricSample{
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			CPUPercent: float64(i),
		}
		if err := store.InsertMetric(ctx, sample); err != nil {
			t.Fatalf("InsertMetric[%d]: %v", i, err)
		}
	}
}

func countRows(t *testing.T, store *SQLiteStore, table string) int64 {
	t.Helper()
	var count int64
	if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func TestTruncateLogsOverCap(t *testing.T) {
	store := openTestDB(t)
	insertTestLogs(t, store, 200)

	tr := NewTruncator(store, 0, 0)
	tr.maxLogRows = 100
	tr.maxMetRows = 100

	if err := tr.truncateOnce(); err != nil {
		t.Fatalf("truncateOnce: %v", err)
	}

	got := countRows(t, store, "logs")
	if got != 80 {
		t.Errorf("logs count = %d, want 80", got)
	}
}

func TestTruncateMetricsOverCap(t *testing.T) {
	store := openTestDB(t)
	insertTestMetrics(t, store, 200)

	tr := NewTruncator(store, 0, 0)
	tr.maxLogRows = 100
	tr.maxMetRows = 100

	if err := tr.truncateOnce(); err != nil {
		t.Fatalf("truncateOnce: %v", err)
	}

	got := countRows(t, store, "metrics")
	if got != 80 {
		t.Errorf("metrics count = %d, want 80", got)
	}
}

func TestTruncateUnderCap(t *testing.T) {
	store := openTestDB(t)
	insertTestLogs(t, store, 50)

	tr := NewTruncator(store, 0, 0)
	tr.maxLogRows = 100
	tr.maxMetRows = 100

	if err := tr.truncateOnce(); err != nil {
		t.Fatalf("truncateOnce: %v", err)
	}

	got := countRows(t, store, "logs")
	if got != 50 {
		t.Errorf("logs count = %d, want 50", got)
	}
}

func TestTruncateDeletesOldest(t *testing.T) {
	store := openTestDB(t)
	insertTestLogs(t, store, 200)

	tr := NewTruncator(store, 0, 0)
	tr.maxLogRows = 100
	tr.maxMetRows = 100

	if err := tr.truncateOnce(); err != nil {
		t.Fatalf("truncateOnce: %v", err)
	}

	// Query remaining logs — should be the newest 80 (log-121 through log-200)
	logs, err := store.QueryLogs(context.Background(), LogFilter{Limit: 1000})
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(logs) != 80 {
		t.Fatalf("remaining logs = %d, want 80", len(logs))
	}

	// First remaining should be log-121
	if logs[0].Line != "log-121" {
		t.Errorf("oldest remaining = %q, want %q", logs[0].Line, "log-121")
	}
	// Last remaining should be log-200
	if logs[len(logs)-1].Line != "log-200" {
		t.Errorf("newest remaining = %q, want %q", logs[len(logs)-1].Line, "log-200")
	}
}

func TestTruncateIncrementalVacuum(t *testing.T) {
	store := openTestDB(t)
	insertTestLogs(t, store, 200)

	tr := NewTruncator(store, 0, 0)
	tr.maxLogRows = 100
	tr.maxMetRows = 100

	// Should complete without error, including the vacuum step.
	if err := tr.truncateOnce(); err != nil {
		t.Fatalf("truncateOnce: %v", err)
	}

	// Verify DB is still functional after vacuum.
	got := countRows(t, store, "logs")
	if got != 80 {
		t.Errorf("logs count = %d, want 80", got)
	}
}

func TestTruncateRunLoop(t *testing.T) {
	store := openTestDB(t)
	insertTestLogs(t, store, 200)

	tr := NewTruncator(store, 0, 0)
	tr.maxLogRows = 100
	tr.maxMetRows = 100
	tr.interval = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Run blocks until ctx is cancelled.
	tr.Run(ctx)

	got := countRows(t, store, "logs")
	if got != 80 {
		t.Errorf("logs count after Run = %d, want 80", got)
	}
}

func TestNewTruncatorBytesToRows(t *testing.T) {
	store := openTestDB(t)

	logCap := int64(10 * 1024 * 1024) // 10 MB
	metCap := int64(18 * 1024 * 1024) // 18 MB

	tr := NewTruncator(store, logCap, metCap)

	wantLogRows := logCap / 200
	wantMetRows := metCap / 150

	if tr.maxLogRows != wantLogRows {
		t.Errorf("maxLogRows = %d, want %d", tr.maxLogRows, wantLogRows)
	}
	if tr.maxMetRows != wantMetRows {
		t.Errorf("maxMetRows = %d, want %d", tr.maxMetRows, wantMetRows)
	}
}
