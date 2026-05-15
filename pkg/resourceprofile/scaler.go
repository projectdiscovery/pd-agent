package resourceprofile

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"slices"
	"sync"
	"time"
)

const (
	defaultScaleInterval = 30 * time.Second
	defaultCooldown      = 60 * time.Second

	// Pressure thresholds (0.0 - 1.0).
	pressureGrowBelow  = 0.75 // grow only when ALL dimensions below 75%
	pressureShrinkAt   = 0.80 // shrink when ANY dimension above 80%
	pressureCriticalAt = 0.90 // shrink hard when ANY dimension above 90%

	// Chunk duration trend: if median duration increases by this ratio
	// compared to baseline, treat it as target-side saturation.
	durationDegradationThreshold = 1.30 // 30% slower
)

// Scaler resizes a ResizableSemaphore based on resource pressure and chunk
// duration trends.
type Scaler struct {
	sem      *ResizableSemaphore
	interval time.Duration
	cooldown time.Duration

	// Chunk duration tracking (rolling window).
	durations   []time.Duration
	durationsMu sync.Mutex
	maxSamples  int

	// Baseline: median duration at the initial parallelism level.
	// Set after the first batch of samples.
	baseline    time.Duration
	baselineSet bool
	baselineMu  sync.Mutex

	// Cooldown tracking.
	lastResize time.Time

	// Actual CPU tracking for pressure measurement.
	prevCPU        cpuSample
	prevCPUTime    time.Time
	lastCPUPercent float64
}

// NewScaler creates a Scaler that adjusts sem based on resource pressure.
func NewScaler(sem *ResizableSemaphore) *Scaler {
	s := &Scaler{
		sem:        sem,
		interval:   defaultScaleInterval,
		cooldown:   defaultCooldown,
		maxSamples: 100,
	}
	s.prevCPU = readCPU()
	s.prevCPUTime = time.Now()
	return s
}

// RecordChunkDuration appends the duration of a completed chunk to the rolling window.
func (s *Scaler) RecordChunkDuration(d time.Duration) {
	s.durationsMu.Lock()
	defer s.durationsMu.Unlock()

	s.durations = append(s.durations, d)
	if len(s.durations) > s.maxSamples {
		s.durations = s.durations[len(s.durations)-s.maxSamples:]
	}
}

// Run starts the control loop and blocks until ctx is cancelled.
func (s *Scaler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluate()
		}
	}
}

func (s *Scaler) evaluate() {
	if time.Since(s.lastResize) < s.cooldown {
		return
	}

	pressure := s.measurePressure()
	durationTrend := s.measureDurationTrend()
	currentSize := s.sem.Size()
	inUse := s.sem.InUse()

	slog.Debug("scaler: evaluate",
		"current_parallelism", currentSize,
		"in_use", inUse,
		"available", currentSize-inUse,
		"cpu_pressure", fmt.Sprintf("%.2f", pressure.cpu),
		"mem_pressure", fmt.Sprintf("%.2f", pressure.mem),
		"fd_pressure", fmt.Sprintf("%.2f", pressure.fd),
		"max_pressure", fmt.Sprintf("%.2f", pressure.max()),
		"duration_trend", fmt.Sprintf("%.2f", durationTrend),
	)

	switch {
	case pressure.max() >= pressureCriticalAt:
		// Critical pressure: halve.
		newSize := currentSize / 2
		if newSize < MinParallelism {
			newSize = MinParallelism
		}
		slog.Warn("scaler: critical pressure, shrinking",
			"from", currentSize, "to", newSize,
			"trigger", pressure.maxDimension(),
			"pressure", fmt.Sprintf("%.2f", pressure.max()),
		)
		s.sem.Resize(newSize)
		s.lastResize = time.Now()

	case pressure.max() >= pressureShrinkAt:
		newSize := currentSize - 1
		if newSize < MinParallelism {
			newSize = MinParallelism
		}
		if newSize != currentSize {
			slog.Info("scaler: high pressure, shrinking",
				"from", currentSize, "to", newSize,
				"trigger", pressure.maxDimension(),
				"pressure", fmt.Sprintf("%.2f", pressure.max()),
			)
			s.sem.Resize(newSize)
			s.lastResize = time.Now()
		}

	case durationTrend > durationDegradationThreshold:
		// Duration climbing while resources are OK indicates target saturation.
		newSize := currentSize - 1
		if newSize < MinParallelism {
			newSize = MinParallelism
		}
		if newSize != currentSize {
			slog.Info("scaler: chunk duration degraded, shrinking",
				"from", currentSize, "to", newSize,
				"duration_trend", fmt.Sprintf("%.2f", durationTrend),
			)
			s.sem.Resize(newSize)
			s.lastResize = time.Now()
			s.resetBaseline()
		}

	case pressure.max() < pressureGrowBelow && inUse >= currentSize:
		// Low pressure with all workers busy: room to grow.
		newSize := currentSize + 1
		if newSize > MaxParallelism {
			newSize = MaxParallelism
		}
		if newSize != currentSize {
			slog.Info("scaler: low pressure, growing",
				"from", currentSize, "to", newSize,
				"max_pressure", fmt.Sprintf("%.2f", pressure.max()),
			)
			s.sem.Resize(newSize)
			s.lastResize = time.Now()
			s.resetBaseline()
		}
	}
}

type resourcePressure struct {
	cpu float64
	mem float64
	fd  float64
}

func (p resourcePressure) max() float64 {
	m := p.cpu
	if p.mem > m {
		m = p.mem
	}
	if p.fd > m {
		m = p.fd
	}
	return m
}

func (p resourcePressure) maxDimension() string {
	m := p.cpu
	dim := "cpu"
	if p.mem > m {
		m = p.mem
		dim = "memory"
	}
	if p.fd > m {
		dim = "fd"
	}
	return dim
}

func (s *Scaler) measurePressure() resourcePressure {
	var p resourcePressure

	memTotal, memAvail := ReadMemory()
	if memTotal > 0 {
		p.mem = 1.0 - float64(memAvail)/float64(memTotal)
	}

	fdUsed, fdLimit := readFDs()
	if fdLimit > 0 {
		p.fd = float64(fdUsed) / float64(fdLimit)
	}

	p.cpu = s.measureCPUPressure()

	return p
}

// measureCPUPressure returns process CPU utilization in [0.0, 1.0],
// normalised by effective CPU count (1.0 = all cores saturated).
func (s *Scaler) measureCPUPressure() float64 {
	now := time.Now()
	current := readCPU()
	elapsed := now.Sub(s.prevCPUTime)

	if elapsed <= 0 {
		return s.lastCPUPercent / 100.0
	}

	// Counter wrap.
	if current.user < s.prevCPU.user || current.system < s.prevCPU.system {
		s.prevCPU = current
		s.prevCPUTime = now
		return 0
	}

	totalDelta := (current.user - s.prevCPU.user) + (current.system - s.prevCPU.system)
	cpuPercent := float64(totalDelta) / float64(elapsed.Nanoseconds()) * 100.0

	s.prevCPU = current
	s.prevCPUTime = now
	s.lastCPUPercent = cpuPercent

	cpus := readEffectiveCPUs()
	if cpus <= 0 {
		cpus = 1
	}
	pressure := cpuPercent / (float64(cpus) * 100.0)
	if pressure > 1.0 {
		pressure = 1.0
	}
	if pressure < 0 {
		pressure = 0
	}
	return pressure
}

// readEffectiveCPUs returns GOMAXPROCS (cgroup-aware after automaxprocs).
func readEffectiveCPUs() int {
	procs := readCgroupCPUs()
	if procs > 0 {
		return int(math.Ceil(procs))
	}
	return goMaxProcs()
}

func goMaxProcs() int {
	return runtime.GOMAXPROCS(0)
}

// measureDurationTrend returns median(recent) / baseline. 1.0 means stable,
// 1.5 means 50% slower.
func (s *Scaler) measureDurationTrend() float64 {
	s.durationsMu.Lock()
	samples := make([]time.Duration, 0, len(s.durations))
	for _, d := range s.durations {
		// Skip fast-skip chunks (naabu found nothing) so they don't drag the baseline.
		if d >= 5*time.Second {
			samples = append(samples, d)
		}
	}
	s.durationsMu.Unlock()

	if len(samples) < 8 {
		return 1.0
	}

	currentMedian := median(samples)

	s.baselineMu.Lock()
	defer s.baselineMu.Unlock()

	if !s.baselineSet {
		s.baseline = currentMedian
		s.baselineSet = true
		return 1.0
	}

	if s.baseline <= 0 {
		return 1.0
	}

	return float64(currentMedian) / float64(s.baseline)
}

func (s *Scaler) resetBaseline() {
	s.baselineMu.Lock()
	s.baselineSet = false
	s.baselineMu.Unlock()

	s.durationsMu.Lock()
	s.durations = s.durations[:0]
	s.durationsMu.Unlock()
}

func median(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)

	slices.Sort(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}
