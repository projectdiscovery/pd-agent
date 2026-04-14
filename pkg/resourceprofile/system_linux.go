//go:build linux

package resourceprofile

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// readRSS returns the resident set size in bytes from /proc/self/status.
func readRSS() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kb * 1024 // convert kB to bytes
				}
			}
		}
	}
	return 0
}

// readMemory returns (total, available) memory in bytes.
// Uses cgroup memory limits first, falls back to /proc/meminfo.
func readMemory() (total, available uint64) {
	// Try cgroup v2 first
	if t, a := readCgroupV2Memory(); t > 0 {
		return t, a
	}
	// Try cgroup v1
	if t, a := readCgroupV1Memory(); t > 0 {
		return t, a
	}
	// Fallback to /proc/meminfo
	return readProcMeminfo()
}

func readCgroupV2Memory() (total, available uint64) {
	limitData, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0, 0
	}
	limitStr := strings.TrimSpace(string(limitData))
	if limitStr == "max" {
		return 0, 0 // no limit, fall through
	}
	total, err = strconv.ParseUint(limitStr, 10, 64)
	if err != nil {
		return 0, 0
	}

	currentData, err := os.ReadFile("/sys/fs/cgroup/memory.current")
	if err != nil {
		return total, total / 2 // guess half available
	}
	current, err := strconv.ParseUint(strings.TrimSpace(string(currentData)), 10, 64)
	if err != nil {
		return total, total / 2
	}

	if current >= total {
		return total, 0
	}
	return total, total - current
}

func readCgroupV1Memory() (total, available uint64) {
	limitData, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	if err != nil {
		return 0, 0
	}
	total, err = strconv.ParseUint(strings.TrimSpace(string(limitData)), 10, 64)
	if err != nil || total >= math.MaxUint64/2 {
		// Extremely large value means no limit
		return 0, 0
	}

	usageData, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes")
	if err != nil {
		return total, total / 2
	}
	usage, err := strconv.ParseUint(strings.TrimSpace(string(usageData)), 10, 64)
	if err != nil {
		return total, total / 2
	}

	if usage >= total {
		return total, 0
	}
	return total, total - usage
}

func readProcMeminfo() (total, available uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(fields[1], 10, 64)
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = kb * 1024
		case strings.HasPrefix(line, "MemAvailable:"):
			available = kb * 1024
		}
	}
	return total, available
}

// readFDs returns (used, limit) file descriptor counts.
func readFDs() (used int, limit int) {
	// Count open FDs
	entries, err := os.ReadDir("/proc/self/fd")
	if err == nil {
		used = len(entries)
	}

	// Get soft limit
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		limit = int(rlimit.Cur)
	}
	return used, limit
}

// readCgroupCPUs returns the effective CPU count from cgroup limits.
// Returns 0 if no cgroup limit is detected (caller should use runtime.NumCPU).
func readCgroupCPUs() float64 {
	// Try cgroup v2
	if cpus := readCgroupV2CPUs(); cpus > 0 {
		return cpus
	}
	// Try cgroup v1
	if cpus := readCgroupV1CPUs(); cpus > 0 {
		return cpus
	}
	return 0
}

func readCgroupV2CPUs() float64 {
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 2 || fields[0] == "max" {
		return 0 // no limit
	}
	quota, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	period, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || period == 0 {
		return 0
	}
	return quota / period
}

func readCgroupV1CPUs() float64 {
	quotaData, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	if err != nil {
		// Try unified hierarchy path
		quotaData, err = os.ReadFile(filepath.Join("/sys/fs/cgroup/cpu,cpuacct", "cpu.cfs_quota_us"))
		if err != nil {
			return 0
		}
	}
	quota, err := strconv.ParseFloat(strings.TrimSpace(string(quotaData)), 64)
	if err != nil || quota < 0 {
		return 0 // -1 means no limit
	}

	periodPath := "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
	periodData, err := os.ReadFile(periodPath)
	if err != nil {
		periodData, err = os.ReadFile(filepath.Join("/sys/fs/cgroup/cpu,cpuacct", "cpu.cfs_period_us"))
		if err != nil {
			return 0
		}
	}
	period, err := strconv.ParseFloat(strings.TrimSpace(string(periodData)), 64)
	if err != nil || period == 0 {
		return 0
	}
	return quota / period
}

// readCPU returns process CPU time from /proc/self/stat.
func readCPU() cpuSample {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return cpuSample{}
	}
	// Fields after the comm (field 2, in parens): find closing paren
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return cpuSample{}
	}
	fields := strings.Fields(s[idx+2:])
	// field[11] = utime (ticks), field[12] = stime (ticks) (0-indexed from after comm)
	if len(fields) < 13 {
		return cpuSample{}
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)

	// Convert clock ticks to nanoseconds (assuming 100 Hz tick rate)
	const tickNs = 10_000_000 // 1e9 / 100
	return cpuSample{
		user:   utime * tickNs,
		system: stime * tickNs,
	}
}
