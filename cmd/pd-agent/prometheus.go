package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// startPrometheusServer exposes /metrics (Prometheus text format) and /healthz
// when PDCP_METRICS_ADDR is set; returns nil otherwise. The HPA scale signal
// is pdagent_group_chunks_pending.
func (r *Runner) startPrometheusServer(_ context.Context) (*http.Server, error) {
	addr := envconfig.MetricsAddr()
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
// Prometheus text format. Returns 503 before NATS is connected so HPA
// scrapers treat it as "no signal yet".
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

// formatFloat renders integer values as integers and real floats compactly.
func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
