package natsrpc

import (
	"context"
	"errors"
	"fmt"
	json "github.com/json-iterator/go"
	"log/slog"
	"maps"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/projectdiscovery/pd-agent/pkg/agentproto"
	"github.com/projectdiscovery/pd-agent/pkg/resourceprofile"
	"google.golang.org/protobuf/proto"
)

const (
	defaultHeartbeatInterval = 10 * time.Second
	defaultAckWait           = 5 * time.Minute
)

// WorkHandler processes a parsed WorkMessage. The raw jetstream.Msg is
// supplied so the handler can ack or nak directly.
type WorkHandler func(ctx context.Context, msg jetstream.Msg, work *WorkMessage) error

// WorkerPool pulls work messages from a JetStream consumer and dispatches
// them to a handler. Concurrency is bounded by parallelism and the consumer's
// MaxAckPending.
type WorkerPool struct {
	js           jetstream.JetStream
	workConsumer jetstream.Consumer
	parallelism  int
	handler      WorkHandler
	wg           sync.WaitGroup
	cancel       context.CancelFunc

	lastActivity  atomic.Int64 // unix nanos of last work start/finish
	activeWorkers atomic.Int32 // number of workers currently processing
}

// NewWorkerPool creates a durable pull consumer filtered to
// groupPrefix.work.>, with MaxAckPending=parallelism so JetStream provides
// the backpressure.
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

// JS returns the underlying JetStream instance.
func (wp *WorkerPool) JS() jetstream.JetStream {
	return wp.js
}

// Run starts the worker goroutines and blocks until ctx is cancelled.
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
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
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
	wp.activeWorkers.Add(1)
	defer wp.activeWorkers.Add(-1)
	wp.touchActivity()

	var work WorkMessage
	if err := json.Unmarshal(msg.Data(), &work); err != nil {
		slog.Error("jetstream worker: unmarshal work message", "worker", workerID, "error", err)
		_ = msg.Term()
		return
	}

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
		// Terminate after too many redeliveries to break poison-pill loops.
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

	wp.touchActivity()
}

func (wp *WorkerPool) touchActivity() {
	wp.lastActivity.Store(time.Now().UnixNano())
}

// LastActivity returns the time of the last work activity, or zero if none.
func (wp *WorkerPool) LastActivity() time.Time {
	nanos := wp.lastActivity.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

// ActiveWorkers returns the number of workers currently processing a message.
func (wp *WorkerPool) ActiveWorkers() int32 {
	return wp.activeWorkers.Load()
}

// IdleSince returns the last-activity time when the pool is idle, or zero
// when it is actively processing or has never processed work.
func (wp *WorkerPool) IdleSince() time.Time {
	if wp.activeWorkers.Load() > 0 {
		return time.Time{}
	}
	return wp.LastActivity()
}

// ChunkScaler receives chunk duration reports for adaptive scaling.
type ChunkScaler interface {
	RecordChunkDuration(d time.Duration)
}

// ConsumeChunks pulls chunks from a shared durable consumer scoped to
// chunkSubject and processes them concurrently. sem caps concurrency; if nil,
// a fixed semaphore of size chunkParallelism is created. scaler is optional.
// processFn errors trigger a nak; ConsumeChunks returns once NumPending == 0.
func ConsumeChunks(
	ctx context.Context,
	js jetstream.JetStream,
	streamName, consumerName, chunkSubject string,
	chunkParallelism int,
	sem *resourceprofile.ResizableSemaphore,
	scaler ChunkScaler,
	processFn func(ctx context.Context, chunk *ChunkMessage) error,
) error {
	if chunkParallelism <= 0 {
		chunkParallelism = 1
	}

	if sem == nil {
		sem = resourceprofile.NewResizableSemaphore(chunkParallelism, chunkParallelism)
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

	var inflightWg sync.WaitGroup
	// scanCtx is detached from ctx so an agent SIGTERM lets chunks drain. It
	// is cancelled explicitly when the consumer is deleted server-side, which
	// makes in-flight nuclei bail mid-template.
	scanCtx, scanCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer func() {
		// consumer.Info inside the fetch loop may return NumPending=0 just
		// before a server-side delete lands. Watch for the delete during the
		// drain so chunks that just started a heavy template load get cancelled.
		drainDone := make(chan struct{})
		go func() {
			inflightWg.Wait()
			close(drainDone)
		}()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-drainDone:
				scanCancel()
				return
			case <-t.C:
				if _, err := consumer.Info(ctx); err != nil && isConsumerOrStreamGone(err) {
					slog.Info("chunk consumer: deleted during drain, cancelling in-flight chunks",
						"stream", streamName, "subject", chunkSubject)
					scanCancel()
					<-drainDone
					return
				}
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		fetchSize := max(sem.Size(), 1)

		batch, err := consumer.Fetch(fetchSize, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isConsumerOrStreamGone(err) {
				slog.Info("chunk consumer: consumer/stream deleted, cancelling in-flight chunks", "stream", streamName, "subject", chunkSubject)
				scanCancel()
				return nil
			}
			slog.Debug("chunk consumer: fetch error", "stream", streamName, "subject", chunkSubject, "error", err)
			time.Sleep(time.Second)
			continue
		}

		gotMessages := false
		for msg := range batch.Messages() {
			gotMessages = true

			// Heartbeat must start before Acquire so the message stays alive
			// while waiting for a processing slot.
			stopHeartbeat := StartHeartbeat(ctx, msg, defaultHeartbeatInterval)

			if err := sem.Acquire(ctx); err != nil {
				stopHeartbeat()
				return err
			}
			inflightWg.Add(1)
			go func(m jetstream.Msg, stopHB context.CancelFunc) {
				defer inflightWg.Done()
				defer sem.Release()
				defer stopHB()
				processCtx := scanCtx
				start := time.Now()
				processChunkMsg(processCtx, m, chunkSubject, processFn)
				if scaler != nil {
					scaler.RecordChunkDuration(time.Since(start))
				}
			}(msg, stopHeartbeat)
		}

		if !gotMessages {
			// Check NumPending only, not NumAckPending. With many agents racing
			// for the same chunks, waiting for NumAckPending==0 would idle agents
			// that finished early until the slow agents catch up. NumPending==0
			// lets each agent exit as soon as no undelivered chunks remain.
			// MaxDeliver=1 means a crash mid-chunk is recovered in the next scan
			// run, not within this one.
			info, err := consumer.Info(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if isConsumerOrStreamGone(err) {
					slog.Info("chunk consumer: consumer/stream deleted, cancelling in-flight chunks", "stream", streamName, "subject", chunkSubject)
					scanCancel()
					return nil
				}
				slog.Warn("chunk consumer: info error", "stream", streamName, "subject", chunkSubject, "error", err)
				continue
			}
			if info.NumPending == 0 {
				slog.Info("chunk consumer: no more chunks to fetch", "stream", streamName, "subject", chunkSubject)
				return nil
			}
		}
	}
}

// isConsumerOrStreamGone reports a server-side delete: retrying will spin forever.
func isConsumerOrStreamGone(err error) bool {
	return errors.Is(err, jetstream.ErrConsumerNotFound) ||
		errors.Is(err, jetstream.ErrConsumerDeleted) ||
		errors.Is(err, jetstream.ErrStreamNotFound)
}

// ZSTD magic number 0xFD2FB528, little-endian.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// zstd.Decoder.DecodeAll is safe for concurrent use, so one decoder suffices.
var zstdDecoder *zstd.Decoder

func init() {
	var err error
	zstdDecoder, err = zstd.NewReader(nil)
	if err != nil {
		panic("zstd init: " + err.Error())
	}
}

// decodeChunkMsg deserializes a chunk message. Scan chunks are
// ZSTD-compressed ScanRequest protobufs; enumeration chunks are plain
// AssetEnrichmentRequest. Discriminated by the ZSTD magic in the first 4 bytes.
func decodeChunkMsg(data []byte) (*ChunkMessage, error) {
	if len(data) >= 4 && data[0] == zstdMagic[0] && data[1] == zstdMagic[1] && data[2] == zstdMagic[2] && data[3] == zstdMagic[3] {
		return decodeScanChunk(data)
	}
	return decodeEnrichmentChunk(data)
}

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

	// Pass private templates through unflattened so each file can be
	// materialized under its real name downstream.
	var privateTemplates map[string]string
	if len(req.PrivateTemplates) > 0 {
		privateTemplates = maps.Clone(req.PrivateTemplates)
	}

	return &ChunkMessage{
		ChunkID:          req.ChunkID,
		Targets:          targets,
		PublicTemplates:  publicTemplates,
		PrivateTemplates: privateTemplates,
		ScanConfig:       string(req.ScanConfiguration),
	}, nil
}

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
	if len(chunk.PrivateTemplates) > 0 {
		logAttrs = append(logAttrs, "private_templates", len(chunk.PrivateTemplates))
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

	// Skip ack when the scan was cancelled server-side; the consumer is gone
	// and DoubleAck would only fail noisily.
	if ctx.Err() != nil {
		slog.Debug("chunk consumer: skipping ack, scan cancelled",
			"subject", chunkSubject,
			"chunk_id", chunk.ChunkID,
		)
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

// ackWithRetry uses DoubleAck (server-confirmed) with jittered backoff.
// Plain Ack is fire-and-forget; a dropped ack would leave the message
// orphaned once consumers stop pulling.
func ackWithRetry(ctx context.Context, msg jetstream.Msg, maxRetries int) error {
	time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)

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
		slog.Debug("ack: retry", "attempt", i+1, "error", err)

		if i < maxRetries {
			backoff := time.Duration(100*(1<<i))*time.Millisecond + time.Duration(rand.IntN(100))*time.Millisecond
			select {
			case <-ctx.Done():
				return fmt.Errorf("ack: context cancelled during backoff: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}
	}
	return fmt.Errorf("ack failed after %d retries: %w", maxRetries+1, err)
}

// StartHeartbeat calls msg.InProgress() every interval to prevent JetStream
// redelivery while the message is being processed. The returned cancel stops it.
func StartHeartbeat(ctx context.Context, msg jetstream.Msg, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		const maxConsecutiveFailures = 3
		consecFails := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := msg.InProgress(); err != nil {
					consecFails++
					slog.Debug("heartbeat: InProgress failed", "error", err, "consecutive_failures", consecFails)
					if consecFails >= maxConsecutiveFailures {
						slog.Warn("heartbeat: giving up after consecutive failures", "consecutive_failures", consecFails)
						return
					}
					continue
				}
				consecFails = 0
			}
		}
	}()
	return cancel
}
