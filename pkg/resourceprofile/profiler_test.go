package resourceprofile

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWithMetricsHook(t *testing.T) {
	t.Helper()

	var mu sync.Mutex
	var snapshots []MetricSnapshot

	hook := func(snap MetricSnapshot) {
		mu.Lock()
		snapshots = append(snapshots, snap)
		mu.Unlock()
	}

	p := New(100*time.Millisecond, func() int32 { return 3 }, WithMetricsHook(hook))

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	mu.Lock()
	defer mu.Unlock()

	if len(snapshots) < 2 {
		t.Fatalf("expected >= 2 snapshots, got %d", len(snapshots))
	}

	snap := snapshots[0]

	if snap.ActiveWorkers != 3 {
		t.Errorf("expected ActiveWorkers=3, got %d", snap.ActiveWorkers)
	}
	if snap.Goroutines <= 0 {
		t.Errorf("expected Goroutines > 0, got %d", snap.Goroutines)
	}
	if snap.HeapAllocMB == 0 && snap.HeapSysMB == 0 {
		t.Errorf("expected at least one heap metric > 0")
	}
}

func TestWithoutMetricsHook(t *testing.T) {
	// Backward compat: profiler without hook must not panic.
	p := New(100*time.Millisecond, func() int32 { return 0 })

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	p.Run(ctx) // must not panic
}
