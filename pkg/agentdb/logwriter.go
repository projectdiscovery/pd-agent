package agentdb

import (
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	logWriterChanSize = 8192
	logWriterMaxBatch = 512
)

// LogWriter is an async, channel-based log writer that batches inserts
// into single transactions.
type LogWriter struct {
	store   *SQLiteStore
	ch      chan LogEntry
	stopped atomic.Bool
	dropped atomic.Int64
	stopCh  chan struct{}
	done    chan struct{}
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
		w.dropped.Add(1)
	}
}

// Run continuously drains the channel, batching inserts into transactions.
// No ticker — flushes as fast as entries arrive.
func (w *LogWriter) Run() {
	defer close(w.done)

	var buf []LogEntry

	for {
		// Block until at least one entry arrives or stop signal.
		select {
		case entry := <-w.ch:
			buf = append(buf, entry)
		case <-w.stopCh:
			w.drain(&buf)
			return
		}

		// Drain everything currently in the channel (non-blocking).
		// This naturally batches: if 200 entries arrived while we were
		// flushing the last batch, we pick them all up in one pass.
	drain:
		for len(buf) < logWriterMaxBatch {
			select {
			case entry := <-w.ch:
				buf = append(buf, entry)
			default:
				break drain
			}
		}

		w.flush(buf)
		buf = buf[:0]
	}
}

// drain collects all remaining entries from the channel into buf and flushes.
func (w *LogWriter) drain(buf *[]LogEntry) {
	for {
		select {
		case entry := <-w.ch:
			*buf = append(*buf, entry)
		default:
			if len(*buf) > 0 {
				w.flush(*buf)
			}
			return
		}
	}
}

// Stop signals the writer to flush remaining entries and exit.
// Blocks until all buffered entries are written to the DB.
func (w *LogWriter) Stop() {
	w.stopped.Store(true)
	close(w.stopCh)
	<-w.done
}

// flush writes a batch of entries in a single transaction.
func (w *LogWriter) flush(entries []LogEntry) {
	if len(entries) == 0 {
		return
	}

	// Always report drops, even if commit fails; otherwise the warn is gated
	// behind a successful flush and the counter grows silently.
	defer func() {
		if dropped := w.dropped.Swap(0); dropped > 0 {
			slog.Warn("agentdb: logwriter dropped entries (channel full)", "dropped", dropped)
		}
	}()

	tx, err := w.store.db.Begin()
	if err != nil {
		slog.Debug("agentdb: logwriter begin tx", "error", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO logs (timestamp, line) VALUES (?, ?)")
	if err != nil {
		_ = tx.Rollback()
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
}
