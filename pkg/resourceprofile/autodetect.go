package resourceprofile

import (
	"log/slog"
	"runtime"
)

const (
	// Per-chunk resource budgets (calibrated from benchmarks + safety margin).
	// Benchmarked: ~40 MB RSS, ~6 FDs per concurrent chunk.
	// Budgeted with safety margin for heavy templates (code, headless).
	MemPerChunkBytes = 200 * 1024 * 1024 // 200 MB
	FDPerChunk       = 20
	FDReserved       = 1024 // FDs reserved for agent itself (NATS, logs, runtime)

	// CPU oversubscribe ratio. Most chunks on large subnets are lightweight
	// (naabu port filter finds nothing → chunk done in 1-2s). Starting higher
	// lets the agent burn through dead IPs fast. The scaler shrinks if a batch
	// of chunks hits live hosts and causes real CPU/memory pressure.
	CPUOversubscribeRatio = 4.0

	// Hard limits.
	MinParallelism = 1
	MaxParallelism = 64
)

// AutoDetectResult holds the computed parallelism and per-dimension breakdown.
type AutoDetectResult struct {
	ChunkParallelism int
	CPUWorkers       int
	MemWorkers       int
	FDWorkers        int
	Bottleneck       string // which dimension was the tightest

	// Detected raw values
	EffectiveCPUs   int
	AvailableMemMB  uint64
	FDLimit         int
	FDUsed          int
}

// ComputeChunkParallelism detects machine resources and computes the optimal
// chunk parallelism using: min(W_cpu, W_mem, W_fd), clamped to [1, 64].
//
// The returned value is the TOTAL number of concurrent chunks the machine can
// handle, regardless of how many scans are running. Global backpressure is
// enforced by the shared ResizableSemaphore in the caller — no per-scan
// division is applied here.
func ComputeChunkParallelism(scanParallelism int) AutoDetectResult {
	// Detect resources
	effectiveCPUs := runtime.GOMAXPROCS(0) // cgroup-aware after automaxprocs
	_, memAvail := readMemory()
	fdUsed, fdLimit := readFDs()

	// Compute per-dimension workers
	cpuWorkers := int(float64(effectiveCPUs) * CPUOversubscribeRatio)
	memWorkers := 0
	if memAvail > 0 {
		memWorkers = int(memAvail / MemPerChunkBytes)
	}
	fdWorkers := 0
	fdAvailable := fdLimit - FDReserved - fdUsed
	if fdAvailable > 0 {
		fdWorkers = fdAvailable / FDPerChunk
	}

	// Tightest constraint wins
	result := cpuWorkers
	bottleneck := "cpu"

	if memWorkers > 0 && memWorkers < result {
		result = memWorkers
		bottleneck = "memory"
	}
	if fdWorkers > 0 && fdWorkers < result {
		result = fdWorkers
		bottleneck = "fd"
	}

	// Clamp
	if result < MinParallelism {
		result = MinParallelism
	}
	if result > MaxParallelism {
		result = MaxParallelism
	}

	return AutoDetectResult{
		ChunkParallelism: result,
		CPUWorkers:       cpuWorkers,
		MemWorkers:       memWorkers,
		FDWorkers:        fdWorkers,
		Bottleneck:       bottleneck,
		EffectiveCPUs:    effectiveCPUs,
		AvailableMemMB:   memAvail / (1024 * 1024),
		FDLimit:          fdLimit,
		FDUsed:           fdUsed,
	}
}

// LogAutoDetectResult logs the full computation for operator visibility.
func LogAutoDetectResult(r AutoDetectResult, source string) {
	slog.Info("chunk parallelism computed",
		"chunk_parallelism", r.ChunkParallelism,
		"source", source,
		"bottleneck", r.Bottleneck,
		"w_cpu", r.CPUWorkers,
		"w_mem", r.MemWorkers,
		"w_fd", r.FDWorkers,
		"effective_cpus", r.EffectiveCPUs,
		"available_mem_mb", r.AvailableMemMB,
		"fd_limit", r.FDLimit,
		"fd_used", r.FDUsed,
	)
}
