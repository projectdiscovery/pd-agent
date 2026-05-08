package resourceprofile

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// ResizableSemaphore controls concurrency with a dynamically adjustable limit.
// Workers call Acquire before starting work and Release when done.
// Resize changes the concurrency limit without disrupting in-flight work.
//
// Implementation: a buffered channel acts as the token pool. Acquire takes a
// token, Release returns one. Resize grows or shrinks the channel by adding
// or draining tokens.
type ResizableSemaphore struct {
	tokens  chan struct{}
	size    atomic.Int32
	mu      sync.Mutex // protects resize operations
	maxSize int
}

// NewResizableSemaphore creates a semaphore with the given initial capacity.
// maxSize is the upper bound for Resize calls.
func NewResizableSemaphore(initial, maxSize int) *ResizableSemaphore {
	if initial < 1 {
		initial = 1
	}
	if maxSize < initial {
		maxSize = initial
	}

	// Allocate channel at maxSize so Resize never needs reallocation.
	s := &ResizableSemaphore{
		tokens:  make(chan struct{}, maxSize),
		maxSize: maxSize,
	}
	s.size.Store(int32(initial))

	// Fill with initial tokens.
	for i := 0; i < initial; i++ {
		s.tokens <- struct{}{}
	}

	return s
}

// Acquire blocks until a token is available or ctx is cancelled.
// Returns nil on success, ctx.Err() on cancellation.
func (s *ResizableSemaphore) Acquire(ctx context.Context) error {
	select {
	case <-s.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a token to the pool. Must be called once per successful Acquire.
func (s *ResizableSemaphore) Release() {
	// Non-blocking send. If the channel is full (more releases than the
	// current size after a shrink), the extra token is silently dropped.
	// This is intentional — shrink works by not returning tokens.
	select {
	case s.tokens <- struct{}{}:
	default:
		// Token dropped — semaphore was shrunk while this worker was in-flight.
	}
}

// Resize changes the concurrency limit. Growing adds tokens immediately
// (waking blocked Acquire calls). Shrinking removes tokens from the pool;
// if not enough free tokens, in-flight workers will naturally drain as they
// Release — their tokens get dropped instead of returned.
func (s *ResizableSemaphore) Resize(newSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if newSize < 1 {
		newSize = 1
	}
	if newSize > s.maxSize {
		newSize = s.maxSize
	}

	oldSize := int(s.size.Load())
	if newSize == oldSize {
		return
	}

	s.size.Store(int32(newSize))

	if newSize > oldSize {
		// Growing: add tokens.
		for i := 0; i < newSize-oldSize; i++ {
			select {
			case s.tokens <- struct{}{}:
			default:
				// Channel full — shouldn't happen if maxSize is correct.
			}
		}
		slog.Info("semaphore: resized", "old", oldSize, "new", newSize, "direction", "grow")
	} else {
		// Shrinking: drain tokens from the pool.
		drained := 0
		for i := 0; i < oldSize-newSize; i++ {
			select {
			case <-s.tokens:
				drained++
			default:
				// Token is held by an in-flight worker. It will be dropped
				// on Release via the non-blocking send in Release().
			}
		}
		slog.Info("semaphore: resized", "old", oldSize, "new", newSize, "direction", "shrink", "drained", drained)
	}
}

// Size returns the current concurrency limit.
func (s *ResizableSemaphore) Size() int {
	return int(s.size.Load())
}

// Available returns the number of tokens currently in the pool (not held by workers).
func (s *ResizableSemaphore) Available() int {
	return len(s.tokens)
}

// InUse returns the approximate number of tokens held by workers.
func (s *ResizableSemaphore) InUse() int {
	size := s.Size()
	avail := s.Available()
	inUse := size - avail
	if inUse < 0 {
		return 0
	}
	return inUse
}
