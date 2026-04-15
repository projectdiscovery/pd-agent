package resourceprofile

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// ActiveWorkersFn returns the current number of active workers.
type ActiveWorkersFn func() int32

// MetricSnapshot is a point-in-time resource measurement passed to the metrics hook.
type MetricSnapshot struct {
	CPUPercent    float64
	RSSMB         uint64
	HeapAllocMB   uint64
	HeapSysMB     uint64
	FDUsed        int
	FDLimit       int
	Goroutines    int
	ActiveWorkers int32
	MemTotalMB    uint64
	MemAvailMB    uint64
}

// MetricsHookFn is called after each profiler sample with the collected metrics.
type MetricsHookFn func(snap MetricSnapshot)

// Option configures the Profiler.
type Option func(*Profiler)

// WithMetricsHook sets a callback invoked after each sample.
func WithMetricsHook(fn MetricsHookFn) Option {
	return func(p *Profiler) {
		p.metricsHook = fn
	}
}

// Profiler samples system resources at a fixed interval and logs them
// as structured slog entries. The output is designed for offline analysis
// to calibrate per-worker resource budgets (memory, FDs, CPU).
type Profiler struct {
	interval       time.Duration
	activeWorkers  ActiveWorkersFn
	prevCPU        cpuSample
	prevSampleTime time.Time
	metricsHook    MetricsHookFn
}

// New creates a Profiler that samples every interval.
// activeWorkers may be nil if the worker pool hasn't started yet.
func New(interval time.Duration, activeWorkers ActiveWorkersFn, opts ...Option) *Profiler {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if activeWorkers == nil {
		activeWorkers = func() int32 { return 0 }
	}
	p := &Profiler{
		interval:      interval,
		activeWorkers: activeWorkers,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Run starts the periodic sampling loop. Blocks until ctx is cancelled.
func (p *Profiler) Run(ctx context.Context) {
	// Take initial CPU sample for delta calculation
	p.prevCPU = readCPU()
	p.prevSampleTime = time.Now()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.sample()
		}
	}
}

// LogStartupResources logs a one-time snapshot of the machine/container
// resources the agent can see. Call this at startup before workers begin.
func LogStartupResources() {
	cpus := runtime.GOMAXPROCS(0)
	numCPU := runtime.NumCPU()
	memTotal, memAvail := readMemory()
	fdUsed, fdLimit := readFDs()
	cgroupCPU := readCgroupCPUs()

	slog.Info("resource_profile: startup",
		"gomaxprocs", cpus,
		"num_cpu", numCPU,
		"cgroup_cpus", fmt.Sprintf("%.2f", cgroupCPU),
		"mem_total_mb", memTotal/(1024*1024),
		"mem_available_mb", memAvail/(1024*1024),
		"fd_used", fdUsed,
		"fd_limit", fdLimit,
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
	)
}

func (p *Profiler) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	fdUsed, fdLimit := readFDs()
	memTotal, memAvail := readMemory()
	workers := p.activeWorkers()
	rss := readRSS()

	// CPU usage since last sample
	now := time.Now()
	currentCPU := readCPU()
	cpuPercent := calcCPUPercent(p.prevCPU, currentCPU, now.Sub(p.prevSampleTime))
	p.prevCPU = currentCPU
	p.prevSampleTime = now

	slog.Debug("resource_profile: sample",
		"active_workers", workers,
		"goroutines", runtime.NumGoroutine(),
		// Memory — Go heap
		"heap_alloc_mb", ms.HeapAlloc/(1024*1024),
		"heap_sys_mb", ms.HeapSys/(1024*1024),
		"heap_objects", ms.HeapObjects,
		"gc_pause_ns", ms.PauseNs[(ms.NumGC+255)%256],
		// Memory — OS level
		"rss_mb", rss/(1024*1024),
		"mem_total_mb", memTotal/(1024*1024),
		"mem_available_mb", memAvail/(1024*1024),
		// File descriptors
		"fd_used", fdUsed,
		"fd_limit", fdLimit,
		// CPU
		"cpu_percent", fmt.Sprintf("%.1f", cpuPercent),
	)

	if p.metricsHook != nil {
		p.metricsHook(MetricSnapshot{
			CPUPercent:    cpuPercent,
			RSSMB:         rss / (1024 * 1024),
			HeapAllocMB:   ms.HeapAlloc / (1024 * 1024),
			HeapSysMB:     ms.HeapSys / (1024 * 1024),
			FDUsed:        fdUsed,
			FDLimit:       fdLimit,
			Goroutines:    runtime.NumGoroutine(),
			ActiveWorkers: workers,
			MemTotalMB:    memTotal / (1024 * 1024),
			MemAvailMB:    memAvail / (1024 * 1024),
		})
	}
}

// ScanSnapshot captures a resource snapshot tied to a scan lifecycle event.
// Call at scan start and end to compute per-scan deltas.
type ScanSnapshot struct {
	ScanID     string
	ChunkID    string
	Event      string // "start" or "end"
	Time       time.Time
	RSS        uint64
	HeapAlloc  uint64
	HeapSys    uint64
	FDUsed     int
	Goroutines int
	Workers    int32
}

// TakeScanSnapshot captures current resource state for a scan event.
func TakeScanSnapshot(scanID, chunkID, event string, activeWorkers int32) ScanSnapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fdUsed, _ := readFDs()

	snap := ScanSnapshot{
		ScanID:     scanID,
		ChunkID:    chunkID,
		Event:      event,
		Time:       time.Now(),
		RSS:        readRSS(),
		HeapAlloc:  ms.HeapAlloc,
		HeapSys:    ms.HeapSys,
		FDUsed:     fdUsed,
		Goroutines: runtime.NumGoroutine(),
		Workers:    activeWorkers,
	}

	slog.Info("resource_profile: scan_snapshot",
		"scan_id", scanID,
		"chunk_id", chunkID,
		"event", event,
		"active_workers", activeWorkers,
		"rss_mb", snap.RSS/(1024*1024),
		"heap_alloc_mb", snap.HeapAlloc/(1024*1024),
		"heap_sys_mb", snap.HeapSys/(1024*1024),
		"fd_used", snap.FDUsed,
		"goroutines", snap.Goroutines,
	)

	return snap
}

// LogScanDelta logs the resource delta between start and end snapshots.
func LogScanDelta(start, end ScanSnapshot) {
	duration := end.Time.Sub(start.Time)
	rssDelta := int64(end.RSS) - int64(start.RSS)
	heapDelta := int64(end.HeapAlloc) - int64(start.HeapAlloc)
	fdDelta := end.FDUsed - start.FDUsed

	slog.Info("resource_profile: scan_delta",
		"scan_id", end.ScanID,
		"chunk_id", end.ChunkID,
		"duration_s", fmt.Sprintf("%.1f", duration.Seconds()),
		"rss_delta_mb", rssDelta/(1024*1024),
		"heap_delta_mb", heapDelta/(1024*1024),
		"fd_delta", fdDelta,
		"goroutine_delta", end.Goroutines-start.Goroutines,
		"workers_at_start", start.Workers,
		"workers_at_end", end.Workers,
	)
}

// cpuSample holds a process CPU time reading for delta calculation.
type cpuSample struct {
	user   uint64 // nanoseconds
	system uint64 // nanoseconds
}

func calcCPUPercent(prev, curr cpuSample, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	// Guard against unsigned underflow if CPU counters wrap.
	if curr.user < prev.user || curr.system < prev.system {
		return 0
	}
	totalDelta := (curr.user - prev.user) + (curr.system - prev.system)
	return float64(totalDelta) / float64(elapsed.Nanoseconds()) * 100.0
}

// Ensure atomic.Int32 satisfies the interface expectation for WorkerPool.
// This helper creates an ActiveWorkersFn from an *atomic.Int32.
func ActiveWorkersFromAtomic(a *atomic.Int32) ActiveWorkersFn {
	return func() int32 {
		if a == nil {
			return 0
		}
		return a.Load()
	}
}
