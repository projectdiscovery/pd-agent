package natsrpc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// TestGroupMetricsCollector_AggregatesAcrossConsumers verifies the collector
// classifies consumer names correctly and sums NumPending / NumAckPending
// across all chunks-* consumers without counting the work consumer twice.
func TestGroupMetricsCollector_AggregatesAcrossConsumers(t *testing.T) {
	ns := startJetStreamServer(t)
	_, js := jsConnect(t, ns)

	createStream(t, js, testStreamName, []string{testGroupPrefix + ".>"})

	// Pre-create two chunk consumers, then publish messages to them.
	mkChunkConsumer := func(name, subject string) {
		_, err := js.CreateOrUpdateConsumer(context.Background(), testStreamName, jetstream.ConsumerConfig{
			Durable:       name,
			FilterSubject: subject,
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       30 * time.Second,
		})
		if err != nil {
			t.Fatalf("create consumer %s: %v", name, err)
		}
	}
	mkChunkConsumer("chunks-scan-A", testGroupPrefix+".chunks.scan-A.>")
	mkChunkConsumer("chunks-scan-B", testGroupPrefix+".chunks.scan-B.>")

	// Work consumer for the local agent.
	const workConsumer = "work-test-agent"
	_, err := js.CreateOrUpdateConsumer(context.Background(), testStreamName, jetstream.ConsumerConfig{
		Durable:       workConsumer,
		FilterSubject: testGroupPrefix + ".work.>",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
	})
	if err != nil {
		t.Fatalf("create work consumer: %v", err)
	}

	// Publish: 5 chunks for scan-A, 3 chunks for scan-B, 2 work messages.
	for i := range 5 {
		publishJSON(t, js, testGroupPrefix+".chunks.scan-A.c"+itoa(i), map[string]any{"i": i})
	}
	for i := range 3 {
		publishJSON(t, js, testGroupPrefix+".chunks.scan-B.c"+itoa(i), map[string]any{"i": i})
	}
	for i := range 2 {
		publishJSON(t, js, testGroupPrefix+".work.scan-"+itoa(i), map[string]any{"i": i})
	}

	c := NewGroupMetricsCollector(js, testStreamName, workConsumer, 1*time.Millisecond)
	got := c.Get(context.Background())

	if got.ChunksPending != 8 {
		t.Errorf("ChunksPending = %d, want 8", got.ChunksPending)
	}
	if got.ChunksInflight != 0 {
		t.Errorf("ChunksInflight = %d, want 0", got.ChunksInflight)
	}
	if got.ActiveScans != 2 {
		t.Errorf("ActiveScans = %d, want 2", got.ActiveScans)
	}
	if got.WorkPending != 2 {
		t.Errorf("WorkPending = %d, want 2", got.WorkPending)
	}
	if got.OldestConsumerAgeSec < 0 {
		t.Errorf("OldestConsumerAgeSec = %d, want >= 0", got.OldestConsumerAgeSec)
	}
	if got.CollectedAt == "" {
		t.Errorf("CollectedAt is empty")
	}
}

// TestGroupMetricsCollector_CacheTTL verifies a fresh snapshot is reused
// across calls within the cache window — same instance pointer returned.
func TestGroupMetricsCollector_CacheTTL(t *testing.T) {
	ns := startJetStreamServer(t)
	_, js := jsConnect(t, ns)
	createStream(t, js, testStreamName, []string{testGroupPrefix + ".>"})

	c := NewGroupMetricsCollector(js, testStreamName, "work-x", 5*time.Second)
	a := c.Get(context.Background())
	b := c.Get(context.Background())
	if a != b {
		t.Errorf("cached Get returned different snapshots: %p vs %p", a, b)
	}
}

// TestGroupMetricsCollector_HandlesMissingStream returns a usable snapshot
// (with CollectionErrors > 0) rather than panicking when the stream does
// not exist yet — matches the early-startup state on a fresh agent.
func TestGroupMetricsCollector_HandlesMissingStream(t *testing.T) {
	ns := startJetStreamServer(t)
	_, js := jsConnect(t, ns)

	c := NewGroupMetricsCollector(js, "DOES-NOT-EXIST", "work-x", 1*time.Millisecond)
	got := c.Get(context.Background())

	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.CollectionErrors == 0 {
		t.Errorf("CollectionErrors = 0, want > 0 on missing stream")
	}
	if got.ChunksPending != 0 {
		t.Errorf("ChunksPending = %d, want 0", got.ChunksPending)
	}
}

// TestGroupMetrics_StringContainsKey ensures the String() helper renders the
// primary signal so log scraping can grep for it.
func TestGroupMetrics_StringContainsKey(t *testing.T) {
	g := &GroupMetrics{ChunksPending: 7, ActiveScans: 1}
	s := g.String()
	if !strings.Contains(s, "chunks_pending=7") {
		t.Errorf("String() = %q, missing chunks_pending=7", s)
	}
}

// itoa avoids strconv import bloat in the tiny test file.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
