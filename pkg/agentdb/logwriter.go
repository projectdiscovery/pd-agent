package agentdb

import (
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	logWriterChanSize      = 1024
	logWriterFlushInterval = 2 * time.Second
	logWriterMaxBatch      = 256
)

// LogWriter is an async, channel-based log writer that batches inserts
// into single transactions.
type LogWriter struct {
	store   *SQLiteStore
	ch      chan LogEntry
	stopped atomic.Bool
	stopCh  chan struct{} // signal to stop
	done    chan struct{} // closed when Run() exits
}

// NewLogWriter creates a LogWriter backed by the given store.
// Call Run() in a goroutine. Call Stop() to flush and shut down.
func NewLogWriter(store *SQLiteStore) *LogWriter {
	return &LogWriter{
		store:  store,
		ch:     make(chan LogEntry, logWriterChanSize),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Write enqueues a log entry. Non-blocking: if the channel is full or
// the writer has stopped, the entry is silently dropped.
func (w *LogWriter) Write(entry LogEntry) {
	if w.stopped.Load() {
		return
	}
	select {
	case w.ch <- entry:
	default:
	}
}

// Run drains the channel, batching inserts into transactions.
// Blocks until Stop() is called. Does NOT depend on context —
// keeps accepting writes through shutdown so diagnostic logs are captured.
func (w *LogWriter) Run() {
	defer close(w.done)

	ticker := time.NewTicker(logWriterFlushInterval)
	defer ticker.Stop()

	var buf []LogEntry

	for {
		select {
		case entry := <-w.ch:
			buf = append(buf, entry)
			if len(buf) >= logWriterMaxBatch {
				w.flush(buf)
				buf = buf[:0]
			}
		case <-ticker.C:
			if len(buf) > 0 {
				w.flush(buf)
				buf = buf[:0]
			}
		case <-w.stopCh:
			// Stop accepting new writes, drain remaining.
			w.stopped.Store(true)
		drain:
			for {
				select {
				case entry := <-w.ch:
					buf = append(buf, entry)
				default:
					break drain
				}
			}
			if len(buf) > 0 {
				w.flush(buf)
			}
			return
		}
	}
}

// Stop signals the writer to flush remaining entries and exit.
// Blocks until all buffered entries are written to the DB.
func (w *LogWriter) Stop() {
	close(w.stopCh)
	<-w.done
}

// flush writes a batch of entries in a single transaction.
func (w *LogWriter) flush(entries []LogEntry) {
	if len(entries) == 0 {
		return
	}

	tx, err := w.store.db.Begin()
	if err != nil {
		slog.Debug("agentdb: logwriter begin tx", "error", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO logs (timestamp, line) VALUES (?, ?)")
	if err != nil {
		tx.Rollback()
		slog.Debug("agentdb: logwriter prepare", "error", err)
		return
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.Exec(e.Timestamp.UTC().Format(time.RFC3339Nano), e.Line); err != nil {
			slog.Debug("agentdb: logwriter insert", "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Debug("agentdb: logwriter commit", "error", err)
		return
	}

	slog.Debug(fmt.Sprintf("agentdb: logwriter flushed %d entries", len(entries)))
}
