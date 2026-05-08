package natsrpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// GroupMetrics aggregates JetStream backlog across the whole agent group.
//
// Every agent in the same group computes the same numbers — the metrics are
// stream-scoped, not per-agent. A customer HPA can scrape any one pod and
// get the group view; the operator can poll any one agent over NATS RPC.
//
// Field semantics:
type GroupMetrics struct {
	// ChunksPending is the count of chunks sitting in the stream that have not
	// yet been delivered to any agent. Sum of NumPending across all
	// "chunks-*" consumers. This is the primary scale-up signal: a rising
	// value means the group cannot keep up with the inbound work.
	ChunksPending int64 `json:"chunks_pending"`

	// ChunksInflight is the count of chunks currently being processed by some
	// agent (delivered, heartbeating, not yet acked). Sum of NumAckPending
	// across all "chunks-*" consumers. Useful to compute true backlog
	// (pending + inflight) versus just queue depth.
	ChunksInflight int64 `json:"chunks_inflight"`

	// ActiveScans is the number of scans the group is currently working on.
	// Counted as "chunks-*" consumers with pending+inflight > 0.
	ActiveScans int64 `json:"active_scans"`

	// WorkPending is the number of scan/enumeration work messages queued to
	// this agent's work consumer but not yet pulled. Because every agent in
	// the group has its own durable work consumer that replays the entire
	// work stream, this value is the same across all agents in the group by
	// construction — so it doubles as a "scans queued, not yet started"
	// signal at the group level.
	WorkPending int64 `json:"work_pending"`

	// OldestConsumerAgeSec is the age in seconds of the oldest active chunk
	// consumer (one with non-zero pending+inflight). 0 if no active scans.
	// A growing value with non-zero ChunksPending indicates the queue is
	// stalled — agents may be stuck or the work is too slow to drain.
	OldestConsumerAgeSec int64 `json:"oldest_consumer_age_seconds"`

	// CollectedAt is when this snapshot was taken (RFC3339 UTC).
	CollectedAt string `json:"collected_at"`

	// CollectionDurationMs is how long the last collection pass took. Useful
	// to spot consumer-list latency growing out of hand.
	CollectionDurationMs int64 `json:"collection_duration_ms"`

	// CollectionErrors is the cumulative count of consumer-info read failures
	// since process start. Treat as a counter for Prometheus, even though we
	// store it as int64 here.
	CollectionErrors int64 `json:"collection_errors_total"`
}

// GroupMetricsCollector walks the JetStream stream once per cache window and
// produces a GroupMetrics snapshot. Safe for concurrent use.
type GroupMetricsCollector struct {
	js               jetstream.JetStream
	streamName       string
	workConsumerName string // "work-<agent_id>" — read for WorkPending
	chunkPrefix      string // "chunks-" — chunk-consumer name filter
	cacheTTL         time.Duration

	cache      atomic.Pointer[GroupMetrics]
	refreshMu  sync.Mutex // serialises refresh paths so concurrent callers piggyback
	errorTotal atomic.Int64
}

// NewGroupMetricsCollector constructs a collector. Pass the JetStream handle
// (typically WorkerPool.JS()), the group stream name, and the agent's local
// work consumer name. cacheTTL controls how often Get triggers a fresh walk.
func NewGroupMetricsCollector(js jetstream.JetStream, streamName, workConsumerName string, cacheTTL time.Duration) *GroupMetricsCollector {
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Second
	}
	return &GroupMetricsCollector{
		js:               js,
		streamName:       streamName,
		workConsumerName: workConsumerName,
		chunkPrefix:      "chunks-",
		cacheTTL:         cacheTTL,
	}
}

// Get returns the most recent snapshot, refreshing if the cache is stale.
// Concurrent callers during a refresh see the previous snapshot until the
// refresh completes — never block.
func (c *GroupMetricsCollector) Get(ctx context.Context) *GroupMetrics {
	if snap := c.cache.Load(); snap != nil {
		if t, err := time.Parse(time.RFC3339Nano, snap.CollectedAt); err == nil && time.Since(t) < c.cacheTTL {
			return snap
		}
	}

	if !c.refreshMu.TryLock() {
		// Another goroutine is refreshing. Return whatever we have, even if stale.
		// First call ever: refreshMu was contended but cache is nil — fall through to a blocking refresh.
		if snap := c.cache.Load(); snap != nil {
			return snap
		}
		c.refreshMu.Lock()
	}
	defer c.refreshMu.Unlock()

	// Re-check after acquiring the lock (another goroutine may have refreshed).
	if snap := c.cache.Load(); snap != nil {
		if t, err := time.Parse(time.RFC3339Nano, snap.CollectedAt); err == nil && time.Since(t) < c.cacheTTL {
			return snap
		}
	}

	snap := c.collect(ctx)
	c.cache.Store(snap)
	return snap
}

// collect performs a single group-state walk: list all consumers, classify by
// name prefix, accumulate pending/inflight totals.
func (c *GroupMetricsCollector) collect(ctx context.Context) *GroupMetrics {
	start := time.Now()
	out := &GroupMetrics{}

	stream, err := c.js.Stream(ctx, c.streamName)
	if err != nil {
		c.errorTotal.Add(1)
		slog.Debug("group metrics: stream lookup failed", "stream", c.streamName, "error", err)
		out.CollectedAt = start.UTC().Format(time.RFC3339Nano)
		out.CollectionDurationMs = time.Since(start).Milliseconds()
		out.CollectionErrors = c.errorTotal.Load()
		return out
	}

	now := time.Now()
	var oldestActive time.Time

	lister := stream.ListConsumers(ctx)
	for info := range lister.Info() {
		if info == nil {
			continue
		}
		switch {
		case info.Name == c.workConsumerName:
			// This agent's work consumer. NumPending = scans queued not yet pulled.
			// Same value across all agents in the group (each agent's consumer replays
			// the same work-stream messages independently), so we expose it as the
			// group-level "WorkPending" without double-counting.
			out.WorkPending = int64(info.NumPending)
		case strings.HasPrefix(info.Name, c.chunkPrefix):
			pending := int64(info.NumPending)
			inflight := int64(info.NumAckPending)
			out.ChunksPending += pending
			out.ChunksInflight += inflight
			if pending+inflight > 0 {
				out.ActiveScans++
				if oldestActive.IsZero() || info.Created.Before(oldestActive) {
					oldestActive = info.Created
				}
			}
		}
	}
	if err := lister.Err(); err != nil && !errors.Is(err, context.Canceled) {
		c.errorTotal.Add(1)
		slog.Debug("group metrics: list consumers error", "stream", c.streamName, "error", err)
	}

	if !oldestActive.IsZero() {
		out.OldestConsumerAgeSec = int64(now.Sub(oldestActive).Seconds())
	}
	out.CollectedAt = start.UTC().Format(time.RFC3339Nano)
	out.CollectionDurationMs = time.Since(start).Milliseconds()
	out.CollectionErrors = c.errorTotal.Load()
	return out
}

// Snapshot returns the last cached snapshot without triggering a refresh.
// Returns a zero-valued snapshot if Get has never run yet — callers can rely
// on a non-nil pointer.
func (c *GroupMetricsCollector) Snapshot() *GroupMetrics {
	if snap := c.cache.Load(); snap != nil {
		return snap
	}
	return &GroupMetrics{
		CollectedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// String renders a single-line summary, useful for logging.
func (g *GroupMetrics) String() string {
	if g == nil {
		return "<nil>"
	}
	return fmt.Sprintf("chunks_pending=%d chunks_inflight=%d active_scans=%d work_pending=%d oldest_age_s=%d",
		g.ChunksPending, g.ChunksInflight, g.ActiveScans, g.WorkPending, g.OldestConsumerAgeSec)
}
