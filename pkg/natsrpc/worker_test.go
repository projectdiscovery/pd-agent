package natsrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/projectdiscovery/pd-agent/pkg/agentproto"
	"google.golang.org/protobuf/proto"
)

// startJetStreamServer creates an in-process NATS server with JetStream enabled.
func startJetStreamServer(t *testing.T) *server.Server {
	t.Helper()
	dir := t.TempDir()
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  dir,
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("failed to create NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(ns.Shutdown)
	return ns
}

func jsConnect(t *testing.T, ns *server.Server) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(nc.Close)

	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	return nc, js
}

// createStream is a test helper to create a JetStream stream.
func createStream(t *testing.T, js jetstream.JetStream, name string, subjects []string) jetstream.Stream {
	t.Helper()
	ctx := context.Background()
	s, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name:     name,
		Subjects: subjects,
		Storage:  jetstream.MemoryStorage,
	})
	if err != nil {
		t.Fatalf("create stream %s: %v", name, err)
	}
	return s
}

func publishJSON(t *testing.T, js jetstream.JetStream, subject string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := js.Publish(context.Background(), subject, data); err != nil {
		t.Fatalf("publish to %s: %v", subject, err)
	}
}

// publishChunk publishes a ScanRequest as ZSTD-compressed protobuf (matching server format).
func publishChunk(t *testing.T, js jetstream.JetStream, subject string, req *agentproto.ScanRequest) {
	t.Helper()
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("proto marshal: %v", err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd encoder: %v", err)
	}
	compressed := enc.EncodeAll(data, nil)
	enc.Close()
	if _, err := js.Publish(context.Background(), subject, compressed); err != nil {
		t.Fatalf("publish chunk to %s: %v", subject, err)
	}
}

// --- Tests ---

// All tests use a single group stream (like Aurora) with subject-filtered consumers.
const (
	testGroupPrefix = "ws-test.scanners"
	testStreamName  = "GRP-test"
)

func TestWorkerPool_ReceivesAndAcksWork(t *testing.T) {
	ns := startJetStreamServer(t)
	nc, js := jsConnect(t, ns)

	// Single group stream capturing all subjects
	createStream(t, js, testStreamName, []string{testGroupPrefix + ".>"})

	// Publish a chunk (ZSTD+protobuf) and work notification to the same stream
	publishChunk(t, js, testGroupPrefix+".scan-1.chunks", &agentproto.ScanRequest{
		ChunkID: "c1",
		Targets: map[string]int64{"example.com": 0},
	})
	publishJSON(t, js, testGroupPrefix+".work.scan", WorkMessage{
		Type:          "scan",
		ScanID:        "test-scan",
		ChunkSubject:  testGroupPrefix + ".scan-1.chunks",
		ChunkConsumer: "test-group",
	})

	var received atomic.Bool
	handler := func(ctx context.Context, msg jetstream.Msg, work *WorkMessage) error {
		if work.ScanID != "test-scan" {
			t.Errorf("unexpected work ID: %s", work.ScanID)
		}
		received.Store(true)
		return nil
	}

	pool, err := NewWorkerPool(nc, testStreamName, "work-test-agent", testGroupPrefix, 1, handler)
	if err != nil {
		t.Fatalf("NewWorkerPool: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool.Run(ctx)

	// Wait for the handler to be called
	deadline := time.After(5 * time.Second)
	for !received.Load() {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for work message")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	pool.Stop()
}

func TestConsumeChunks_ProcessesAllChunks(t *testing.T) {
	ns := startJetStreamServer(t)
	_, js := jsConnect(t, ns)

	// Single group stream
	createStream(t, js, testStreamName, []string{testGroupPrefix + ".>"})

	chunkSubject := testGroupPrefix + ".scan-1.chunks"

	// Pre-populate 5 chunks (ZSTD+protobuf) on the chunk subject
	for i := 1; i <= 5; i++ {
		publishChunk(t, js, chunkSubject, &agentproto.ScanRequest{
			ChunkID: fmt.Sprintf("c%d", i),
			Targets: map[string]int64{fmt.Sprintf("target-%d.example.com", i): 0},
		})
	}

	var mu sync.Mutex
	processed := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := ConsumeChunks(ctx, js, testStreamName, "test-group", chunkSubject, 1,
		func(ctx context.Context, chunk *ChunkMessage) error {
			mu.Lock()
			processed[chunk.ChunkID] = true
			mu.Unlock()
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ConsumeChunks: %v", err)
	}

	if len(processed) != 5 {
		t.Errorf("expected 5 chunks processed, got %d", len(processed))
	}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("c%d", i)
		if !processed[id] {
			t.Errorf("chunk %s not processed", id)
		}
	}
}

func TestConsumeChunks_CompetingConsumers(t *testing.T) {
	ns := startJetStreamServer(t)
	_, js := jsConnect(t, ns)

	createStream(t, js, testStreamName, []string{testGroupPrefix + ".>"})

	chunkSubject := testGroupPrefix + ".scan-compete.chunks"

	chunkCount := 20
	for i := 1; i <= chunkCount; i++ {
		publishChunk(t, js, chunkSubject, &agentproto.ScanRequest{
			ChunkID: fmt.Sprintf("c%d", i),
			Targets: map[string]int64{"example.com": 0},
		})
	}

	var mu sync.Mutex
	agent1Chunks := make(map[string]bool)
	agent2Chunks := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Agent 1 — same consumer name = shared (competing)
	go func() {
		defer wg.Done()
		_ = ConsumeChunks(ctx, js, testStreamName, "shared-group", chunkSubject, 1,
			func(ctx context.Context, chunk *ChunkMessage) error {
				mu.Lock()
				agent1Chunks[chunk.ChunkID] = true
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				return nil
			},
		)
	}()

	// Agent 2 — same consumer name
	go func() {
		defer wg.Done()
		_ = ConsumeChunks(ctx, js, testStreamName, "shared-group", chunkSubject, 1,
			func(ctx context.Context, chunk *ChunkMessage) error {
				mu.Lock()
				agent2Chunks[chunk.ChunkID] = true
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				return nil
			},
		)
	}()

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	total := len(agent1Chunks) + len(agent2Chunks)
	if total != chunkCount {
		t.Errorf("expected %d total chunks processed, got %d (agent1=%d, agent2=%d)",
			chunkCount, total, len(agent1Chunks), len(agent2Chunks))
	}

	// Verify no chunk was processed by both agents
	for id := range agent1Chunks {
		if agent2Chunks[id] {
			t.Errorf("chunk %s processed by both agents", id)
		}
	}

	if len(agent1Chunks) == 0 || len(agent2Chunks) == 0 {
		t.Logf("warning: work not distributed (agent1=%d, agent2=%d) — may be timing dependent",
			len(agent1Chunks), len(agent2Chunks))
	}
}

func TestStartHeartbeat_CallsInProgress(t *testing.T) {
	ns := startJetStreamServer(t)
	nc, js := jsConnect(t, ns)

	createStream(t, js, "HB-TEST", []string{"hb.>"})
	publishJSON(t, js, "hb.msg", map[string]string{"test": "heartbeat"})

	consumer, err := js.CreateOrUpdateConsumer(context.Background(), "HB-TEST", jetstream.ConsumerConfig{
		Durable:   "hb-consumer",
		AckPolicy: jetstream.AckExplicitPolicy,
		AckWait:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}

	batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	var msg jetstream.Msg
	for m := range batch.Messages() {
		msg = m
	}
	if msg == nil {
		t.Fatal("no message received")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopHB := StartHeartbeat(ctx, msg, 500*time.Millisecond)

	time.Sleep(3 * time.Second)
	stopHB()

	if err := msg.Ack(); err != nil {
		t.Fatalf("ack: %v", err)
	}

	info, err := consumer.Info(context.Background())
	if err != nil {
		t.Fatalf("consumer info: %v", err)
	}
	if info.NumRedelivered > 0 {
		t.Errorf("message was redelivered despite heartbeat (redelivered=%d)", info.NumRedelivered)
	}

	_ = nc
}

func TestMaxAckPending_LimitsConcurrentWork(t *testing.T) {
	ns := startJetStreamServer(t)
	nc, js := jsConnect(t, ns)

	// Single group stream with work subject filter
	createStream(t, js, "GRP-LIMIT", []string{"limit.>"})

	for i := 1; i <= 5; i++ {
		publishJSON(t, js, "limit.work.scan", WorkMessage{
			Type: "scan",
			ScanID: fmt.Sprintf("scan-%d", i),
		})
	}

	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32

	handler := func(ctx context.Context, msg jetstream.Msg, work *WorkMessage) error {
		cur := concurrent.Add(1)
		for {
			old := maxConcurrent.Load()
			if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
		concurrent.Add(-1)
		return nil
	}

	pool, err := NewWorkerPool(nc, "GRP-LIMIT", "work-limit-agent", "limit", 2, handler)
	if err != nil {
		t.Fatalf("NewWorkerPool: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool.Run(ctx)

	time.Sleep(3 * time.Second)
	pool.Stop()

	mc := maxConcurrent.Load()
	if mc > 2 {
		t.Errorf("max concurrent exceeded parallelism: got %d, want <= 2", mc)
	}
	if mc == 0 {
		t.Error("no work was processed")
	}
}

// TestFilterSubject_WorkerOnlySeesWorkMessages verifies the FilterSubject on
// the work consumer — it should only receive work.> messages, not chunk messages
// published to the same stream.
func TestFilterSubject_WorkerOnlySeesWorkMessages(t *testing.T) {
	ns := startJetStreamServer(t)
	nc, js := jsConnect(t, ns)

	createStream(t, js, testStreamName, []string{testGroupPrefix + ".>"})

	// Publish chunks (should NOT be delivered to work consumer)
	for i := 0; i < 10; i++ {
		publishChunk(t, js, testGroupPrefix+".scan-1.chunks", &agentproto.ScanRequest{
			ChunkID: fmt.Sprintf("c%d", i),
			Targets: map[string]int64{"example.com": 0},
		})
	}

	// Publish one work message
	publishJSON(t, js, testGroupPrefix+".work.scan", WorkMessage{
		Type: "scan",
		ScanID: "only-work",
	})

	var receivedIDs []string
	var mu sync.Mutex

	handler := func(ctx context.Context, msg jetstream.Msg, work *WorkMessage) error {
		mu.Lock()
		receivedIDs = append(receivedIDs, work.ScanID)
		mu.Unlock()
		return nil
	}

	pool, err := NewWorkerPool(nc, testStreamName, "work-filter-agent", testGroupPrefix, 1, handler)
	if err != nil {
		t.Fatalf("NewWorkerPool: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool.Run(ctx)
	time.Sleep(2 * time.Second)
	pool.Stop()

	mu.Lock()
	defer mu.Unlock()

	if len(receivedIDs) != 1 || receivedIDs[0] != "only-work" {
		t.Errorf("expected exactly 1 work message 'only-work', got %v", receivedIDs)
	}
}
