package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/agentdb"
)

// dbWriter is an io.Writer that captures slog output and stores it in SQLite.
// Used as the second writer in io.MultiWriter(os.Stderr, dbWriter).
type dbWriter struct {
	mu        sync.Mutex
	logWriter *agentdb.LogWriter
	earlyLogs []string // buffered before DB ready, cap 1000
}

// Write captures each slog line and sends it to the LogWriter.
func (w *dbWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	if line == "" {
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.logWriter != nil {
		w.logWriter.Write(agentdb.LogEntry{
			Timestamp: time.Now().UTC(),
			Line:      line,
		})
	} else if len(w.earlyLogs) < 1000 {
		w.earlyLogs = append(w.earlyLogs, line)
	}

	return len(p), nil
}

// SetLogWriter enables writing to SQLite and flushes early buffered logs.
func (w *dbWriter) SetLogWriter(lw *agentdb.LogWriter) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logWriter = lw
	for _, line := range w.earlyLogs {
		lw.Write(agentdb.LogEntry{
			Timestamp: time.Now().UTC(),
			Line:      line,
		})
	}
	w.earlyLogs = nil
}

// ClearLogWriter disables writing (call before DB close on shutdown).
func (w *dbWriter) ClearLogWriter() {
	w.mu.Lock()
	w.logWriter = nil
	w.mu.Unlock()
}

// StopLogWriter stops the LogWriter (flush + drain) and then clears it.
func (w *dbWriter) StopLogWriter() {
	w.mu.Lock()
	lw := w.logWriter
	w.logWriter = nil
	w.mu.Unlock()
	if lw != nil {
		lw.Stop()
	}
}

// DirectWrite bypasses the async LogWriter and writes directly to SQLite.
// Use this in panic recovery where the async channel may not flush in time.
func (w *dbWriter) DirectWrite(store agentdb.Store, line string) {
	if store == nil {
		return
	}
	_ = store.InsertLog(context.Background(), &agentdb.LogEntry{
		Timestamp: time.Now().UTC(),
		Line:      line,
	})
}

// dbWriterInstance is the global writer, wired at startup.
var dbWriterInstance *dbWriter

// initLogging configures slog to write to both stderr and the dbWriter.
func initLogging(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	dbWriterInstance = &dbWriter{}
	multi := io.MultiWriter(os.Stderr, dbWriterInstance)
	slog.SetDefault(slog.New(slog.NewTextHandler(multi, &slog.HandlerOptions{Level: level})))
}
