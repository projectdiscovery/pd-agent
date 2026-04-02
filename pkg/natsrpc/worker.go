package natsrpc

import (
	"context"
	json "github.com/json-iterator/go"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/projectdiscovery/pd-agent/pkg/agentproto"
	"google.golang.org/protobuf/proto"
)

const (
	defaultHeartbeatInterval = 10 * time.Second
	defaultAckWait           = 5 * time.Minute
	defaultFetchTimeout      = 30 * time.Second
)

// WorkHandler processes a work message (scan or enumeration).
// The handler receives the raw JetStream message for ack/nak control
// and the parsed WorkMessage payload.
type WorkHandler func(ctx context.Context, msg jetstream.Msg, work *WorkMessage) error

// WorkerPool manages a pool of goroutines that pull work messages from a
// JetStream consumer and dispatch them to a handler. Each worker pulls one
// work message at a time; concurrency is controlled by the pool size and
// MaxAckPending on the consumer.
type WorkerPool struct {
	js           jetstream.JetStream
	workConsumer jetstream.Consumer
	parallelism  int
	handler      WorkHandler
	wg           sync.WaitGroup
	cancel       context.CancelFunc
}

// NewWorkerPool creates a WorkerPool that consumes work notifications from
// the group stream. It creates a durable pull consumer with a FilterSubject
// scoped to groupPrefix.work.> so it only receives work messages, not chunks
// or other messages in the same stream.
//
// The consumer's MaxAckPending is set to parallelism so JetStream itself acts
// as the backpressure mechanism.
func NewWorkerPool(nc *nats.Conn, streamName, consumerName, groupPrefix string, parallelism int, handler WorkHandler) (*WorkerPool, error) {
	if parallelism <= 0 {
		parallelism = 1
	}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	consumer, err := js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:       consumerName,
		FilterSubject: groupPrefix + ".work.>",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       defaultAckWait,
		MaxAckPending: parallelism,
	})
	if err != nil {
		return nil, fmt.Errorf("create work consumer %q on stream %q (filter=%s.work.>): %w", consumerName, streamName, groupPrefix, err)
	}

	return &WorkerPool{
		js:           js,
		workConsumer: consumer,
		parallelism:  parallelism,
		handler:      handler,
	}, nil
}

// JS returns the underlying JetStream instance for use by chunk consumers.
func (wp *WorkerPool) JS() jetstream.JetStream {
	return wp.js
}

// Run starts the worker goroutines. Each worker pulls one work message at a
// time from the consumer, starts a heartbeat, dispatches to the handler, and
// acks/naks based on the result. Run blocks until ctx is cancelled.
func (wp *WorkerPool) Run(ctx context.Context) {
	ctx, wp.cancel = context.WithCancel(ctx)

	for i := 0; i < wp.parallelism; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}
}

// Stop signals workers to stop and waits for in-flight work to complete.
func (wp *WorkerPool) Stop() {
	if wp.cancel != nil {
		wp.cancel()
	}
	wp.wg.Wait()
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	for {
		if ctx.Err() != nil {
			return
		}

		batch, err := wp.workConsumer.Fetch(1, jetstream.FetchContext(ctx))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("jetstream worker: fetch error", "worker", id, "error", err)
			time.Sleep(time.Second) // brief backoff on transient errors
			continue
		}

		for msg := range batch.Messages() {
			wp.processMessage(ctx, id, msg)
		}

		if err := batch.Error(); err != nil {
			slog.Debug("jetstream worker: batch error", "worker", id, "error", err)
		}
	}
}

func (wp *WorkerPool) processMessage(ctx context.Context, workerID int, msg jetstream.Msg) {
	var work WorkMessage
	if err := json.Unmarshal(msg.Data(), &work); err != nil {
		slog.Error("jetstream worker: unmarshal work message", "worker", workerID, "error", err)
		_ = msg.Term() // permanent failure, don't redeliver
		return
	}

	// Include NATS metadata (stream seq, num delivered) to identify redeliveries
	meta, _ := msg.Metadata()
	var streamSeq, numDelivered uint64
	if meta != nil {
		streamSeq = meta.Sequence.Stream
		numDelivered = meta.NumDelivered
	}
	slog.Info("jetstream worker: received work",
		"worker", workerID,
		"type", work.Type,
		"id", work.ScanID,
		"chunk_subject", work.ChunkSubject,
		"stream_seq", streamSeq,
		"num_delivered", numDelivered,
	)

	// Start heartbeat on the work message to prevent redelivery
	stopHeartbeat := StartHeartbeat(ctx, msg, defaultHeartbeatInterval)
	defer stopHeartbeat()

	if err := wp.handler(ctx, msg, &work); err != nil {
		slog.Error("jetstream worker: handler failed",
			"worker", workerID,
			"type", work.Type,
			"id", work.ScanID,
			"stream_seq", streamSeq,
			"num_delivered", numDelivered,
			"error", err,
		)
		// After too many redeliveries, terminate the message to stop poison-pill loops.
		// Otherwise nak for retry.
		if numDelivered > 5 {
			slog.Error("jetstream worker: terminating poison message after too many redeliveries",
				"worker", workerID,
				"id", work.ScanID,
				"stream_seq", streamSeq,
				"num_delivered", numDelivered,
			)
			_ = msg.Term()
		} else {
			_ = msg.Nak()
		}
		return
	}

	if err := ackWithRetry(ctx, msg, 3); err != nil {
		slog.Error("jetstream worker: ack failed",
			"worker", workerID,
			"type", work.Type,
			"id", work.ScanID,
			"stream_seq", streamSeq,
			"error", err,
		)
	} else {
		slog.Info("jetstream worker: work completed",
			"worker", workerID,
			"type", work.Type,
			"id", work.ScanID,
			"stream_seq", streamSeq,
		)
	}
}

// ConsumeChunks pulls and processes chunks from the group stream using a shared
// durable consumer with a FilterSubject scoped to the scan's chunk subject.
// All agents in the same group bind to the same consumer name, so each chunk
// is delivered to exactly one agent.
//
// processFn is called for each chunk. If it returns an error, the chunk is
// nak'd for redelivery. ConsumeChunks returns when the stream is drained
// (no pending messages and fetch returns empty).
func ConsumeChunks(
	ctx context.Context,
	js jetstream.JetStream,
	streamName, consumerName, chunkSubject string,
	chunkParallelism int,
	processFn func(ctx context.Context, chunk *ChunkMessage) error,
) error {
	if chunkParallelism <= 0 {
		chunkParallelism = 1
	}

	consumer, err := js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:       consumerName,
		FilterSubject: chunkSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       defaultAckWait,
		MaxDeliver:    1,
	})
	if err != nil {
		return fmt.Errorf("bind chunk consumer %q on stream %q (filter=%s): %w", consumerName, streamName, chunkSubject, err)
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		batch, err := consumer.Fetch(chunkParallelism, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Debug("chunk consumer: fetch error", "stream", streamName, "subject", chunkSubject, "error", err)
			time.Sleep(time.Second)
			continue
		}

		gotMessages := false
		for msg := range batch.Messages() {
			gotMessages = true
			processChunkMsg(ctx, msg, chunkSubject, processFn)
		}

		if !gotMessages {
			// No messages available — check if there are any undelivered chunks left.
			//
			// We intentionally check only NumPending (undelivered messages), NOT
			// NumAckPending (delivered but unacked). This enables the multi-agent
			// flow-through pattern:
			//
			//   100 agents race for 1000 chunks on scan-1.
			//   990 chunks done, 10 agents still processing their last chunk.
			//   90 agents fetch → empty → NumPending=0 → done → ACK scan-1 → move to scan-2.
			//   The 10 agents finish their chunks → also see NumPending=0 → move on.
			//
			// If we waited for NumAckPending==0 (all agents done), those 90 agents
			// would idle-loop until the last 10 finish — defeating the purpose of
			// distributed chunk processing.
			//
			// Crash safety: if an agent crashes mid-chunk, AckWait expires and the
			// chunk becomes pending again (NumPending > 0). Agents still on this
			// scan will pick it up on their next fetch.
			info, err := consumer.Info(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				slog.Warn("chunk consumer: info error", "stream", streamName, "subject", chunkSubject, "error", err)
				continue
			}
			if info.NumPending == 0 {
				slog.Info("chunk consumer: no more chunks to fetch", "stream", streamName, "subject", chunkSubject)
				return nil
			}
			// Chunks still pending delivery — keep trying
		}
	}
}

// ZSTD magic number: 0xFD2FB528 (little-endian)
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// Package-level zstd decoder — reused across all chunk decodes.
// zstd.Decoder.DecodeAll is safe for concurrent use.
var zstdDecoder *zstd.Decoder

func init() {
	var err error
	zstdDecoder, err = zstd.NewReader(nil)
	if err != nil {
		panic("zstd init: " + err.Error())
	}
}

// decodeChunkMsg deserializes a chunk message from NATS.
// Scan chunks are ZSTD-compressed protobuf (ScanRequest).
// Enumeration chunks are plain protobuf (AssetEnrichmentRequest).
// Detection is based on the ZSTD magic number in the first 4 bytes.
func decodeChunkMsg(data []byte) (*ChunkMessage, error) {
	if len(data) >= 4 && data[0] == zstdMagic[0] && data[1] == zstdMagic[1] && data[2] == zstdMagic[2] && data[3] == zstdMagic[3] {
		return decodeScanChunk(data)
	}
	return decodeEnrichmentChunk(data)
}

// decodeScanChunk handles ZSTD-compressed protobuf ScanRequest chunks.
func decodeScanChunk(data []byte) (*ChunkMessage, error) {
	decompressed, err := zstdDecoder.DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress: %w", err)
	}

	var req agentproto.ScanRequest
	if err := proto.Unmarshal(decompressed, &req); err != nil {
		return nil, fmt.Errorf("proto unmarshal ScanRequest: %w", err)
	}

	targets := make([]string, 0, len(req.Targets))
	for t := range req.Targets {
		targets = append(targets, t)
	}

	publicTemplates := make([]string, 0, len(req.PublicTemplates))
	for t := range req.PublicTemplates {
		publicTemplates = append(publicTemplates, t)
	}

	privateTemplates := make([]string, 0, len(req.PrivateTemplates))
	for t := range req.PrivateTemplates {
		privateTemplates = append(privateTemplates, t)
	}

	return &ChunkMessage{
		ChunkID:          req.ChunkID,
		Targets:          targets,
		PublicTemplates:  publicTemplates,
		PrivateTemplates: privateTemplates,
		ScanConfig:       string(req.ScanConfiguration),
	}, nil
}

// decodeEnrichmentChunk handles plain protobuf AssetEnrichmentRequest chunks.
func decodeEnrichmentChunk(data []byte) (*ChunkMessage, error) {
	var req agentproto.AssetEnrichmentRequest
	if err := proto.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("proto unmarshal AssetEnrichmentRequest: %w", err)
	}

	targets := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		if t.Host != "" {
			targets = append(targets, t.Host)
		} else if t.DomainName != "" {
			targets = append(targets, t.DomainName)
		}
	}

	return &ChunkMessage{
		ChunkID:        req.ChunkID,
		Targets:        targets,
		EnrichmentID:   req.EnrichmentID,
		EnrichmentType: req.Type.String(),
		EnumConfig:     string(req.EnumerationConfiguration),
	}, nil
}

func processChunkMsg(
	ctx context.Context,
	msg jetstream.Msg,
	chunkSubject string,
	processFn func(ctx context.Context, chunk *ChunkMessage) error,
) {
	chunk, err := decodeChunkMsg(msg.Data())
	if err != nil {
		slog.Error("chunk consumer: decode chunk failed", "subject", chunkSubject, "error", err)
		_ = msg.Term()
		return
	}

	logAttrs := []any{
		"subject", chunkSubject,
		"chunk_id", chunk.ChunkID,
		"targets", len(chunk.Targets),
	}
	if len(chunk.PublicTemplates) > 0 {
		logAttrs = append(logAttrs, "templates", len(chunk.PublicTemplates))
	}
	if chunk.EnrichmentType != "" {
		logAttrs = append(logAttrs, "enrichment_type", chunk.EnrichmentType)
	}
	if chunk.EnrichmentID != "" {
		logAttrs = append(logAttrs, "enrichment_id", chunk.EnrichmentID)
	}
	if len(chunk.Targets) > 0 && len(chunk.Targets) <= 5 {
		logAttrs = append(logAttrs, "target_list", chunk.Targets)
	} else if len(chunk.Targets) > 5 {
		logAttrs = append(logAttrs, "first_targets", chunk.Targets[:5])
	}
	slog.Info("chunk consumer: processing chunk", logAttrs...)

	stopHeartbeat := StartHeartbeat(ctx, msg, defaultHeartbeatInterval)
	defer stopHeartbeat()

	if err := processFn(ctx, chunk); err != nil {
		slog.Error("chunk consumer: process failed",
			"subject", chunkSubject,
			"chunk_id", chunk.ChunkID,
			"error", err,
		)
		_ = msg.Nak()
		return
	}

	if err := ackWithRetry(ctx, msg, 3); err != nil {
		slog.Error("chunk consumer: ack failed",
			"subject", chunkSubject,
			"chunk_id", chunk.ChunkID,
			"error", err,
		)
	}
}

// ackWithRetry acknowledges a message using DoubleAck (server-confirmed) with
// retry logic. Plain Ack() is fire-and-forget — if the ack packet is lost, the
// message stays unacked and can become orphaned when no consumers are pulling.
func ackWithRetry(ctx context.Context, msg jetstream.Msg, maxRetries int) error {
	var err error
	for i := 0; i <= maxRetries; i++ {
		ackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = msg.DoubleAck(ackCtx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("ack: context cancelled: %w", ctx.Err())
		}
		slog.Warn("ack: retry", "attempt", i+1, "error", err)
	}
	return fmt.Errorf("ack failed after %d retries: %w", maxRetries+1, err)
}

// StartHeartbeat spawns a goroutine that calls msg.InProgress() at the given
// interval to prevent JetStream from redelivering the message while it is
// being processed. Returns a cancel function to stop the heartbeat.
func StartHeartbeat(ctx context.Context, msg jetstream.Msg, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := msg.InProgress(); err != nil {
					slog.Debug("heartbeat: InProgress failed", "error", err)
					return
				}
			}
		}
	}()
	return cancel
}
