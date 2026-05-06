package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// startPrometheusServer starts a minimal HTTP server exposing /metrics in
// Prometheus text format and /healthz for liveness checks. Returns nil if
// PDCP_METRICS_ADDR is unset (feature is opt-in).
//
// We hand-roll the text format rather than pulling in client_golang because
// the surface is six gauges plus one counter — the upside of the dep does not
// justify the weight.
//
// The customer wires their HPA to scrape /metrics and scale the agent
// Deployment based on pdagent_group_chunks_pending (the primary signal).
func (r *Runner) startPrometheusServer(_ context.Context) (*http.Server, error) {
	addr := os.Getenv("PDCP_METRICS_ADDR")
	if addr == "" {
		return nil, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", r.servePrometheusMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("prometheus: server exited", "addr", addr, "error", err)
		}
	}()
	slog.Info("prometheus: serving /metrics", "addr", addr)
	return srv, nil
}

// servePrometheusMetrics writes the current group-metrics snapshot in
// Prometheus text exposition format. Each metric carries HELP and TYPE
// comments so the meaning is self-documenting at the scrape target.
//
// Returns 503 if the metrics collector is not yet initialised (NATS not
// connected); HPA scrapers should treat that as "no signal yet".
func (r *Runner) servePrometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	collector := r.groupMetrics.Load()
	if collector == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "# group metrics collector not initialised yet\n")
		return
	}
	g := collector.Get(r.ctx)
	if g == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "# no snapshot available\n")
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	writeGauge(w,
		"pdagent_group_chunks_pending",
		"Chunks waiting in the stream, not yet delivered to any agent. Primary scale signal: rising means the group cannot keep up with inbound work.",
		float64(g.ChunksPending))

	writeGauge(w,
		"pdagent_group_chunks_inflight",
		"Chunks currently being processed by some agent (delivered, heartbeating, not yet acked).",
		float64(g.ChunksInflight))

	writeGauge(w,
		"pdagent_group_active_scans",
		"Number of scans the group is currently working on (chunk consumers with non-zero pending+inflight).",
		float64(g.ActiveScans))

	writeGauge(w,
		"pdagent_group_work_pending",
		"Scans queued in the work stream but not yet started by any agent. Same value across all agents in the group.",
		float64(g.WorkPending))

	writeGauge(w,
		"pdagent_group_oldest_consumer_age_seconds",
		"Age in seconds of the oldest active chunk consumer. A growing value with non-zero chunks_pending indicates a stalled queue.",
		float64(g.OldestConsumerAgeSec))

	writeGauge(w,
		"pdagent_group_collection_duration_milliseconds",
		"Time spent collecting the last group metrics snapshot.",
		float64(g.CollectionDurationMs))

	writeCounter(w,
		"pdagent_group_collection_errors_total",
		"Total consumer-info read failures since process start.",
		float64(g.CollectionErrors))
}

func writeGauge(w io.Writer, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n",
		name, help, name, name, formatFloat(value))
}

func writeCounter(w io.Writer, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %s\n",
		name, help, name, name, formatFloat(value))
}

// formatFloat renders an integer value without a decimal point and a real
// float with as few digits as needed. Prometheus accepts either, but integer
// values render cleanly without the trailing ".000000".
func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
