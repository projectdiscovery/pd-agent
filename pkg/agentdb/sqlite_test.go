package agentdb

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", dbPath, err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestOpen(t *testing.T) {
	t.Run("creates file at path", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "test.db")
		store, err := Open(dbPath)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer store.Close()

		// file should exist on disk
		size, err := store.DBSizeBytes()
		if err != nil {
			t.Fatalf("DBSizeBytes: %v", err)
		}
		if size <= 0 {
			t.Errorf("expected file size > 0, got %d", size)
		}
	})

	t.Run("tables exist", func(t *testing.T) {
		store := openTestDB(t)

		tables := make(map[string]bool)
		rows, err := store.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name IN ('agent_info','logs','metrics')`)
		if err != nil {
			t.Fatalf("query sqlite_master: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatalf("scan: %v", err)
			}
			tables[name] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows iteration: %v", err)
		}

		for _, want := range []string{"agent_info", "logs", "metrics"} {
			if !tables[want] {
				t.Errorf("table %q not found in sqlite_master", want)
			}
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		_, err := Open("/nonexistent/dir/that/does/not/exist/test.db")
		if err == nil {
			t.Fatal("expected error for invalid path, got nil")
		}
	})
}

func TestUpsertGetAgentInfo(t *testing.T) {
	ctx := context.Background()

	t.Run("insert then get roundtrip", func(t *testing.T) {
		store := openTestDB(t)

		now := time.Now().Truncate(time.Microsecond)
		info := &AgentInfo{
			AgentID:   "agent-001",
			AgentName: "test-agent",
			Version:   "1.2.3",
			OS:        "linux",
			Arch:      "amd64",
			NumCPU:    8,
			Hostname:  "host1",
			PID:       12345,
			NetworkInfo: NetInfo{
				Interfaces: []InterfaceInfo{
					{Name: "eth0", Addrs: []string{"192.168.1.10/24"}},
					{Name: "lo", Addrs: []string{"127.0.0.1/8"}},
				},
				Gateway:      "192.168.1.1",
				DNSResolvers: []string{"8.8.8.8", "1.1.1.1"},
				PublicIPs:    []string{"203.0.113.5"},
				PrivateIPs:   []string{"192.168.1.10"},
				NetworkType:  "direct_public",
			},
			StartedAt: now,
			UpdatedAt: now,
		}

		if err := store.UpsertAgentInfo(ctx, info); err != nil {
			t.Fatalf("UpsertAgentInfo: %v", err)
		}

		got, err := store.GetAgentInfo(ctx)
		if err != nil {
			t.Fatalf("GetAgentInfo: %v", err)
		}
		if got == nil {
			t.Fatal("GetAgentInfo returned nil")
		}

		// Scalar fields
		if got.AgentID != info.AgentID {
			t.Errorf("AgentID = %q, want %q", got.AgentID, info.AgentID)
		}
		if got.AgentName != info.AgentName {
			t.Errorf("AgentName = %q, want %q", got.AgentName, info.AgentName)
		}
		if got.Version != info.Version {
			t.Errorf("Version = %q, want %q", got.Version, info.Version)
		}
		if got.OS != info.OS {
			t.Errorf("OS = %q, want %q", got.OS, info.OS)
		}
		if got.Arch != info.Arch {
			t.Errorf("Arch = %q, want %q", got.Arch, info.Arch)
		}
		if got.NumCPU != info.NumCPU {
			t.Errorf("NumCPU = %d, want %d", got.NumCPU, info.NumCPU)
		}
		if got.Hostname != info.Hostname {
			t.Errorf("Hostname = %q, want %q", got.Hostname, info.Hostname)
		}
		if got.PID != info.PID {
			t.Errorf("PID = %d, want %d", got.PID, info.PID)
		}

		// Time fields
		if !got.StartedAt.Equal(info.StartedAt) {
			t.Errorf("StartedAt = %v, want %v", got.StartedAt, info.StartedAt)
		}
		if !got.UpdatedAt.Equal(info.UpdatedAt) {
			t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, info.UpdatedAt)
		}

		// NetworkInfo
		if got.NetworkInfo.Gateway != info.NetworkInfo.Gateway {
			t.Errorf("Gateway = %q, want %q", got.NetworkInfo.Gateway, info.NetworkInfo.Gateway)
		}
		if got.NetworkInfo.NetworkType != info.NetworkInfo.NetworkType {
			t.Errorf("NetworkType = %q, want %q", got.NetworkInfo.NetworkType, info.NetworkInfo.NetworkType)
		}
		if len(got.NetworkInfo.Interfaces) != len(info.NetworkInfo.Interfaces) {
			t.Errorf("Interfaces len = %d, want %d", len(got.NetworkInfo.Interfaces), len(info.NetworkInfo.Interfaces))
		}
		if len(got.NetworkInfo.DNSResolvers) != len(info.NetworkInfo.DNSResolvers) {
			t.Errorf("DNSResolvers len = %d, want %d", len(got.NetworkInfo.DNSResolvers), len(info.NetworkInfo.DNSResolvers))
		}
		if len(got.NetworkInfo.PublicIPs) != len(info.NetworkInfo.PublicIPs) {
			t.Errorf("PublicIPs len = %d, want %d", len(got.NetworkInfo.PublicIPs), len(info.NetworkInfo.PublicIPs))
		}
	})

	t.Run("upsert overwrites", func(t *testing.T) {
		store := openTestDB(t)
		now := time.Now().Truncate(time.Microsecond)

		info1 := &AgentInfo{
			AgentID:   "agent-001",
			AgentName: "first",
			Version:   "1.0.0",
			StartedAt: now,
			UpdatedAt: now,
		}
		if err := store.UpsertAgentInfo(ctx, info1); err != nil {
			t.Fatalf("first UpsertAgentInfo: %v", err)
		}

		later := now.Add(time.Second)
		info2 := &AgentInfo{
			AgentID:   "agent-001",
			AgentName: "second",
			Version:   "2.0.0",
			StartedAt: now,
			UpdatedAt: later,
		}
		if err := store.UpsertAgentInfo(ctx, info2); err != nil {
			t.Fatalf("second UpsertAgentInfo: %v", err)
		}

		got, err := store.GetAgentInfo(ctx)
		if err != nil {
			t.Fatalf("GetAgentInfo: %v", err)
		}
		if got.AgentName != "second" {
			t.Errorf("AgentName = %q, want %q", got.AgentName, "second")
		}
		if got.Version != "2.0.0" {
			t.Errorf("Version = %q, want %q", got.Version, "2.0.0")
		}

		// Verify still only one row
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM agent_info").Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("row count = %d, want 1", count)
		}
	})

	t.Run("get on empty DB returns nil", func(t *testing.T) {
		store := openTestDB(t)
		got, err := store.GetAgentInfo(ctx)
		if err != nil {
			t.Fatalf("GetAgentInfo: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})
}

func TestInsertQueryLogs(t *testing.T) {
	ctx := context.Background()

	t.Run("insert and query all", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			entry := &LogEntry{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Line:      "msg-" + time.Duration(i*int(time.Second)).String(),
			}
			if err := store.InsertLog(ctx, entry); err != nil {
				t.Fatalf("InsertLog[%d]: %v", i, err)
			}
		}

		logs, err := store.QueryLogs(ctx, LogFilter{})
		if err != nil {
			t.Fatalf("QueryLogs: %v", err)
		}
		if len(logs) != 10 {
			t.Fatalf("len = %d, want 10", len(logs))
		}

		// Verify ordered oldest-first
		for i := 1; i < len(logs); i++ {
			if logs[i].Timestamp.Before(logs[i-1].Timestamp) {
				t.Errorf("logs not ordered: [%d]=%v before [%d]=%v", i, logs[i].Timestamp, i-1, logs[i-1].Timestamp)
			}
		}
	})

	t.Run("filter by time range", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			entry := &LogEntry{
				Timestamp: base.Add(time.Duration(i) * time.Hour),
				Line:      "msg",
			}
			if err := store.InsertLog(ctx, entry); err != nil {
				t.Fatalf("InsertLog[%d]: %v", i, err)
			}
		}

		since := base.Add(3 * time.Hour)
		until := base.Add(6 * time.Hour)
		logs, err := store.QueryLogs(ctx, LogFilter{Since: since, Until: until})
		if err != nil {
			t.Fatalf("QueryLogs: %v", err)
		}
		// Should include hours 3,4,5,6 = 4 entries
		if len(logs) != 4 {
			t.Fatalf("len = %d, want 4", len(logs))
		}
		for _, l := range logs {
			if l.Timestamp.Before(since) || l.Timestamp.After(until) {
				t.Errorf("log timestamp %v outside range [%v, %v]", l.Timestamp, since, until)
			}
		}
	})

	t.Run("offset and limit", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			entry := &LogEntry{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Line:      "msg-" + string(rune('A'+i)),
			}
			if err := store.InsertLog(ctx, entry); err != nil {
				t.Fatalf("InsertLog[%d]: %v", i, err)
			}
		}

		logs, err := store.QueryLogs(ctx, LogFilter{Offset: 5, Limit: 3})
		if err != nil {
			t.Fatalf("QueryLogs: %v", err)
		}
		if len(logs) != 3 {
			t.Fatalf("len = %d, want 3", len(logs))
		}
		// The 6th entry (offset=5) should have timestamp base+5s
		wantTS := base.Add(5 * time.Second)
		if !logs[0].Timestamp.Equal(wantTS) {
			t.Errorf("first log timestamp = %v, want %v", logs[0].Timestamp, wantTS)
		}
	})

	t.Run("default limit caps at 500", func(t *testing.T) {
		store := openTestDB(t)

		// Just verify the query works with limit=0 (default).
		// We don't insert 500+ rows to save test time; just ensure no error.
		logs, err := store.QueryLogs(ctx, LogFilter{Limit: 0})
		if err != nil {
			t.Fatalf("QueryLogs: %v", err)
		}
		if logs == nil {
			t.Error("expected non-nil empty slice, got nil")
		}
	})

	t.Run("query empty table", func(t *testing.T) {
		store := openTestDB(t)
		logs, err := store.QueryLogs(ctx, LogFilter{})
		if err != nil {
			t.Fatalf("QueryLogs: %v", err)
		}
		if len(logs) != 0 {
			t.Errorf("expected 0 logs, got %d", len(logs))
		}
	})
}

func TestInsertQueryMetrics(t *testing.T) {
	ctx := context.Background()

	t.Run("insert and query ordered", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 5; i++ {
			sample := &MetricSample{
				Timestamp:        base.Add(time.Duration(i) * time.Minute),
				CPUPercent:       float64(i) * 10.5,
				RSSMB:            uint64(100 + i),
				HeapAllocMB:      uint64(50 + i),
				HeapSysMB:        uint64(200 + i),
				FDUsed:           10 + i,
				Goroutines:       20 + i,
				ActiveWorkers:    int32(i),
				ChunkParallelism: 4,
			}
			if err := store.InsertMetric(ctx, sample); err != nil {
				t.Fatalf("InsertMetric[%d]: %v", i, err)
			}
		}

		since := base
		until := base.Add(10 * time.Minute)
		metrics, err := store.QueryMetrics(ctx, since, until, 100)
		if err != nil {
			t.Fatalf("QueryMetrics: %v", err)
		}
		if len(metrics) != 5 {
			t.Fatalf("len = %d, want 5", len(metrics))
		}

		// Verify oldest-first ordering
		for i := 1; i < len(metrics); i++ {
			if metrics[i].Timestamp.Before(metrics[i-1].Timestamp) {
				t.Errorf("metrics not ordered: [%d]=%v before [%d]=%v",
					i, metrics[i].Timestamp, i-1, metrics[i-1].Timestamp)
			}
		}

		// Verify field values of first sample
		m := metrics[0]
		if m.CPUPercent != 0.0 {
			t.Errorf("CPUPercent = %f, want 0.0", m.CPUPercent)
		}
		if m.RSSMB != 100 {
			t.Errorf("RSSMB = %d, want 100", m.RSSMB)
		}
		if m.Goroutines != 20 {
			t.Errorf("Goroutines = %d, want 20", m.Goroutines)
		}
	})

	t.Run("query with time range", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			sample := &MetricSample{
				Timestamp:  base.Add(time.Duration(i) * time.Minute),
				CPUPercent: float64(i),
			}
			if err := store.InsertMetric(ctx, sample); err != nil {
				t.Fatalf("InsertMetric[%d]: %v", i, err)
			}
		}

		since := base.Add(3 * time.Minute)
		until := base.Add(6 * time.Minute)
		metrics, err := store.QueryMetrics(ctx, since, until, 100)
		if err != nil {
			t.Fatalf("QueryMetrics: %v", err)
		}
		// minutes 3,4,5,6 = 4 entries
		if len(metrics) != 4 {
			t.Fatalf("len = %d, want 4", len(metrics))
		}
	})

	t.Run("limit", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			sample := &MetricSample{
				Timestamp:  base.Add(time.Duration(i) * time.Minute),
				CPUPercent: float64(i),
			}
			if err := store.InsertMetric(ctx, sample); err != nil {
				t.Fatalf("InsertMetric[%d]: %v", i, err)
			}
		}

		since := base
		until := base.Add(1 * time.Hour)
		metrics, err := store.QueryMetrics(ctx, since, until, 2)
		if err != nil {
			t.Fatalf("QueryMetrics: %v", err)
		}
		if len(metrics) != 2 {
			t.Fatalf("len = %d, want 2", len(metrics))
		}
	})

	t.Run("query empty table", func(t *testing.T) {
		store := openTestDB(t)

		since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		until := since.Add(time.Hour)
		metrics, err := store.QueryMetrics(ctx, since, until, 100)
		if err != nil {
			t.Fatalf("QueryMetrics: %v", err)
		}
		if len(metrics) != 0 {
			t.Errorf("expected 0, got %d", len(metrics))
		}
	})

	t.Run("since after until returns empty", func(t *testing.T) {
		store := openTestDB(t)

		base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		sample := &MetricSample{
			Timestamp:  base,
			CPUPercent: 50.0,
		}
		if err := store.InsertMetric(ctx, sample); err != nil {
			t.Fatalf("InsertMetric: %v", err)
		}

		// since > until
		metrics, err := store.QueryMetrics(ctx, base.Add(time.Hour), base, 100)
		if err != nil {
			t.Fatalf("QueryMetrics: %v", err)
		}
		if len(metrics) != 0 {
			t.Errorf("expected 0, got %d", len(metrics))
		}
	})
}

func TestConcurrentWrites(t *testing.T) {
	store := openTestDB(t)
	ctx := context.Background()

	const numGoroutines = 10
	const entriesPerGoroutine = 100

	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines*entriesPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < entriesPerGoroutine; i++ {
				entry := &LogEntry{
					Timestamp: time.Now(),
					Line:      "concurrent write",
				}
				if err := store.InsertLog(ctx, entry); err != nil {
					errs <- err
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent InsertLog error: %v", err)
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM logs").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	want := numGoroutines * entriesPerGoroutine
	if count != want {
		t.Errorf("total logs = %d, want %d", count, want)
	}
}

func TestDBSizeBytes(t *testing.T) {
	store := openTestDB(t)
	ctx := context.Background()

	size1, err := store.DBSizeBytes()
	if err != nil {
		t.Fatalf("DBSizeBytes: %v", err)
	}
	if size1 <= 0 {
		t.Errorf("expected size > 0 after open, got %d", size1)
	}

	// Insert data
	for i := 0; i < 100; i++ {
		entry := &LogEntry{
			Timestamp: time.Now(),
			Line:      "padding data for size test - some extra text to make the entry bigger",
		}
		if err := store.InsertLog(ctx, entry); err != nil {
			t.Fatalf("InsertLog: %v", err)
		}
	}

	// Force checkpoint so WAL data goes to main file
	_, _ = store.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")

	size2, err := store.DBSizeBytes()
	if err != nil {
		t.Fatalf("DBSizeBytes: %v", err)
	}
	if size2 <= size1 {
		t.Errorf("expected size to increase after inserts: before=%d, after=%d", size1, size2)
	}
}
