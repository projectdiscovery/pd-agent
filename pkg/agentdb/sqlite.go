package agentdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store backed by a local SQLite database.
type SQLiteStore struct {
	db     *sql.DB
	dbPath string
}

// compile-time check
var _ Store = (*SQLiteStore)(nil)

const schema = `
CREATE TABLE IF NOT EXISTS agent_info (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    agent_id       TEXT NOT NULL,
    agent_name     TEXT NOT NULL DEFAULT '',
    agent_network  TEXT NOT NULL DEFAULT '',
    use_jetstream  INTEGER NOT NULL DEFAULT 0,
    version        TEXT NOT NULL DEFAULT '',
    os             TEXT NOT NULL DEFAULT '',
    arch           TEXT NOT NULL DEFAULT '',
    num_cpu        INTEGER NOT NULL DEFAULT 0,
    hostname       TEXT NOT NULL DEFAULT '',
    pid            INTEGER NOT NULL DEFAULT 0,
    network_info   TEXT NOT NULL DEFAULT '{}',
    startup_args   TEXT NOT NULL DEFAULT '[]',
    startup_env    TEXT NOT NULL DEFAULT '{}',
    started_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    line      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);

CREATE TABLE IF NOT EXISTS metrics (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT NOT NULL,
    cpu_percent       REAL NOT NULL DEFAULT 0,
    rss_mb            INTEGER NOT NULL DEFAULT 0,
    heap_alloc_mb     INTEGER NOT NULL DEFAULT 0,
    heap_sys_mb       INTEGER NOT NULL DEFAULT 0,
    fd_used           INTEGER NOT NULL DEFAULT 0,
    fd_limit          INTEGER NOT NULL DEFAULT 0,
    mem_total_mb      INTEGER NOT NULL DEFAULT 0,
    mem_avail_mb      INTEGER NOT NULL DEFAULT 0,
    goroutines        INTEGER NOT NULL DEFAULT 0,
    active_workers    INTEGER NOT NULL DEFAULT 0,
    chunk_parallelism INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
`

// Open creates or opens a SQLite database at dbPath and returns an SQLiteStore.
func Open(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("agentdb: open %s: %w", dbPath, err)
	}

	// SQLite only supports one writer at a time. Serialise all access through
	// a single connection so concurrent goroutines never hit SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	// Verify the connection is usable (catches bad paths).
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("agentdb: ping %s: %w", dbPath, err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("agentdb: %s: %w", p, err)
		}
	}

	// auto_vacuum can only be set before the first table is created.
	// On existing databases, the pragma is silently ignored. Check and
	// convert if needed (one-time VACUUM to restructure the file).
	var avMode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&avMode); err == nil && avMode == 0 {
		if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			db.Close()
			return nil, fmt.Errorf("agentdb: set auto_vacuum: %w", err)
		}
		// VACUUM converts the file to incremental auto_vacuum mode.
		// One-time cost on first open of an existing DB without auto_vacuum.
		if _, err := db.Exec("VACUUM"); err != nil {
			slog.Warn("agentdb: VACUUM to enable auto_vacuum failed (non-fatal)", "error", err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("agentdb: create schema: %w", err)
	}

	return &SQLiteStore{db: db, dbPath: dbPath}, nil
}

// UpsertAgentInfo inserts or replaces the single agent_info row (id=1).
func (s *SQLiteStore) UpsertAgentInfo(ctx context.Context, info *AgentInfo) error {
	netJSON, err := json.Marshal(info.NetworkInfo)
	if err != nil {
		return fmt.Errorf("agentdb: marshal network_info: %w", err)
	}

	jsInt := 0
	if info.UseJetStream {
		jsInt = 1
	}

	const q = `INSERT OR REPLACE INTO agent_info
		(id, agent_id, agent_name, agent_network, use_jetstream, version, os, arch, num_cpu, hostname, pid, network_info, startup_args, startup_env, started_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, q,
		info.AgentID,
		info.AgentName,
		info.AgentNetwork,
		jsInt,
		info.Version,
		info.OS,
		info.Arch,
		info.NumCPU,
		info.Hostname,
		info.PID,
		string(netJSON),
		info.StartupArgs,
		info.StartupEnv,
		info.StartedAt.UTC().Format(time.RFC3339Nano),
		info.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("agentdb: upsert agent_info: %w", err)
	}
	return nil
}

// GetAgentInfo returns the current agent info, or (nil, nil) if no row exists.
func (s *SQLiteStore) GetAgentInfo(ctx context.Context) (*AgentInfo, error) {
	const q = `SELECT agent_id, agent_name, agent_network, use_jetstream, version, os, arch, num_cpu, hostname, pid,
		network_info, startup_args, startup_env, started_at, updated_at FROM agent_info WHERE id = 1`

	var (
		info      AgentInfo
		netJSON   string
		jsInt     int
		startedAt string
		updatedAt string
	)

	err := s.db.QueryRowContext(ctx, q).Scan(
		&info.AgentID,
		&info.AgentName,
		&info.AgentNetwork,
		&jsInt,
		&info.Version,
		&info.OS,
		&info.Arch,
		&info.NumCPU,
		&info.Hostname,
		&info.PID,
		&netJSON,
		&info.StartupArgs,
		&info.StartupEnv,
		&startedAt,
		&updatedAt,
	)
	info.UseJetStream = jsInt != 0
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agentdb: get agent_info: %w", err)
	}

	if err := json.Unmarshal([]byte(netJSON), &info.NetworkInfo); err != nil {
		return nil, fmt.Errorf("agentdb: unmarshal network_info: %w", err)
	}

	info.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return nil, fmt.Errorf("agentdb: parse started_at: %w", err)
	}
	info.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("agentdb: parse updated_at: %w", err)
	}

	return &info, nil
}

// InsertLog appends a structured log entry.
func (s *SQLiteStore) InsertLog(ctx context.Context, entry *LogEntry) error {
	const q = `INSERT INTO logs (timestamp, line) VALUES (?, ?)`
	_, err := s.db.ExecContext(ctx, q, entry.Timestamp.UTC().Format(time.RFC3339Nano), entry.Line)
	if err != nil {
		return fmt.Errorf("agentdb: insert log: %w", err)
	}
	return nil
}

// InsertMetric appends a resource metrics sample.
func (s *SQLiteStore) InsertMetric(ctx context.Context, sample *MetricSample) error {
	const q = `INSERT INTO metrics
		(timestamp, cpu_percent, rss_mb, heap_alloc_mb, heap_sys_mb, fd_used, fd_limit, mem_total_mb, mem_avail_mb, goroutines, active_workers, chunk_parallelism)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, q,
		sample.Timestamp.UTC().Format(time.RFC3339Nano),
		sample.CPUPercent,
		sample.RSSMB,
		sample.HeapAllocMB,
		sample.HeapSysMB,
		sample.FDUsed,
		sample.FDLimit,
		sample.MemTotalMB,
		sample.MemAvailMB,
		sample.Goroutines,
		sample.ActiveWorkers,
		sample.ChunkParallelism,
	)
	if err != nil {
		return fmt.Errorf("agentdb: insert metric: %w", err)
	}
	return nil
}

// QueryLogs returns log entries matching the filter, ordered oldest-first.
func (s *SQLiteStore) QueryLogs(ctx context.Context, filter LogFilter) ([]LogEntry, error) {
	var (
		where []string
		args  []any
	)

	if !filter.Since.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	if !filter.Until.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, filter.Until.UTC().Format(time.RFC3339Nano))
	}

	q := "SELECT id, timestamp, line FROM logs"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id ASC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 500
	}
	q += fmt.Sprintf(" LIMIT %d", limit)

	if filter.Offset > 0 {
		q += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("agentdb: query logs: %w", err)
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var (
			e  LogEntry
			ts string
		)
		if err := rows.Scan(&e.ID, &ts, &e.Line); err != nil {
			return nil, fmt.Errorf("agentdb: scan log: %w", err)
		}
		e.Timestamp, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("agentdb: parse log timestamp: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentdb: rows iteration: %w", err)
	}

	// Return empty slice instead of nil for consistency.
	if entries == nil {
		entries = []LogEntry{}
	}
	return entries, nil
}

// QueryMetrics returns metric samples within [since, until], ordered oldest-first.
func (s *SQLiteStore) QueryMetrics(ctx context.Context, since, until time.Time, limit int) ([]MetricSample, error) {
	const q = `SELECT id, timestamp, cpu_percent, rss_mb, heap_alloc_mb, heap_sys_mb,
		fd_used, fd_limit, mem_total_mb, mem_avail_mb, goroutines, active_workers, chunk_parallelism
		FROM metrics
		WHERE timestamp >= ? AND timestamp <= ?
		ORDER BY id ASC
		LIMIT ?`

	// SQLite LIMIT -1 means no limit. LIMIT 0 returns 0 rows.
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.QueryContext(ctx, q,
		since.UTC().Format(time.RFC3339Nano),
		until.UTC().Format(time.RFC3339Nano),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("agentdb: query metrics: %w", err)
	}
	defer rows.Close()

	var samples []MetricSample
	for rows.Next() {
		var (
			m  MetricSample
			ts string
		)
		if err := rows.Scan(
			&m.ID, &ts, &m.CPUPercent, &m.RSSMB, &m.HeapAllocMB, &m.HeapSysMB,
			&m.FDUsed, &m.FDLimit, &m.MemTotalMB, &m.MemAvailMB,
			&m.Goroutines, &m.ActiveWorkers, &m.ChunkParallelism,
		); err != nil {
			return nil, fmt.Errorf("agentdb: scan metric: %w", err)
		}
		m.Timestamp, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("agentdb: parse metric timestamp: %w", err)
		}
		samples = append(samples, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentdb: rows iteration: %w", err)
	}

	if samples == nil {
		samples = []MetricSample{}
	}
	return samples, nil
}

// DBSizeBytes returns the current database file size in bytes.
func (s *SQLiteStore) DBSizeBytes() (int64, error) {
	fi, err := os.Stat(s.dbPath)
	if err != nil {
		return 0, fmt.Errorf("agentdb: stat %s: %w", s.dbPath, err)
	}
	return fi.Size(), nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
