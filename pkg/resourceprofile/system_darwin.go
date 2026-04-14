//go:build darwin

package resourceprofile

import (
	"bufio"
	"encoding/binary"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// readRSS returns the resident set size in bytes via getrusage.
func readRSS() uint64 {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return 0
	}
	// macOS reports maxrss in bytes (unlike Linux which reports kB)
	return uint64(rusage.Maxrss)
}

// readMemory returns (total, available) memory in bytes.
// On macOS there is no direct "available memory" syscall. We parse vm_stat
// output for free + inactive pages to approximate available memory. If that
// fails, we fall back to 50% of total as a conservative safety heuristic.
func readMemory() (total, available uint64) {
	total = readSysctlUint64("hw.memsize")
	if total == 0 {
		return 0, 0
	}

	if avail, ok := readVMStatAvailable(); ok && avail > 0 && avail < total {
		return total, avail
	}

	// Fallback: 50% of total is conservative but safe for resource budgeting.
	slog.Warn("resource_profile: vm_stat unavailable, using 50%% of total as available memory estimate",
		"total_mb", total/(1024*1024))
	return total, total / 2
}

// readVMStatAvailable parses `vm_stat` output to compute available memory
// from (Pages free + Pages inactive) * page_size. This is the closest
// approximation to Linux's MemAvailable on macOS.
func readVMStatAvailable() (uint64, bool) {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0, false
	}

	const pageSize = 4096

	var free, inactive uint64
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Pages free:") {
			free = parseVMStatValue(line)
		} else if strings.HasPrefix(line, "Pages inactive:") {
			inactive = parseVMStatValue(line)
		}
	}

	if free == 0 && inactive == 0 {
		return 0, false
	}
	return (free + inactive) * pageSize, true
}

// parseVMStatValue extracts the numeric page count from a vm_stat line.
// Lines look like: "Pages free:                               12345."
func parseVMStatValue(line string) uint64 {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	s := strings.TrimSpace(parts[1])
	s = strings.TrimSuffix(s, ".")
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readSysctlUint64(name string) uint64 {
	val, err := syscall.Sysctl(name)
	if err != nil || len(val) < 8 {
		return 0
	}
	// sysctl returns the value as a binary blob in host byte order.
	// Use encoding/binary instead of unsafe pointer arithmetic.
	return binary.LittleEndian.Uint64([]byte(val)[:8])
}

// readFDs returns (used, limit) file descriptor counts.
func readFDs() (used int, limit int) {
	// Count open FDs by probing — no /proc on macOS.
	// Use getrlimit for the limit.
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		limit = int(rlimit.Cur)
	}

	// Probe open FDs up to limit (capped for performance)
	maxProbe := limit
	if maxProbe > 4096 {
		maxProbe = 4096
	}
	for fd := 0; fd < maxProbe; fd++ {
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); err == nil {
			used++
		}
	}
	return used, limit
}

// readCgroupCPUs returns 0 on macOS — no cgroup support.
func readCgroupCPUs() float64 {
	return 0
}

// readCPU returns process CPU time via getrusage.
func readCPU() cpuSample {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return cpuSample{}
	}
	return cpuSample{
		user:   uint64(rusage.Utime.Sec)*1e9 + uint64(rusage.Utime.Usec)*1e3,
		system: uint64(rusage.Stime.Sec)*1e9 + uint64(rusage.Stime.Usec)*1e3,
	}
}
