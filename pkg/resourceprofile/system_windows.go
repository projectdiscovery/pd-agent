//go:build windows

package resourceprofile

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modPsapi   = windows.NewLazySystemDLL("psapi.dll")
	modKernel  = windows.NewLazySystemDLL("kernel32.dll")
	procGetPMI = modPsapi.NewProc("GetProcessMemoryInfo")
	procGetPHC = modKernel.NewProc("GetProcessHandleCount")
	procGMSE   = modKernel.NewProc("GlobalMemoryStatusEx")
)

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// readRSS returns the working set size (RSS equivalent) on Windows.
func readRSS() uint64 {
	h := windows.CurrentProcess()
	var pmc processMemoryCounters
	size := uint32(unsafe.Sizeof(pmc))
	ret, _, _ := procGetPMI.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(size))
	if ret == 0 {
		return 0
	}
	return uint64(pmc.WorkingSetSize)
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// readMemory returns (total, available) physical memory on Windows.
func ReadMemory() (total, available uint64) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	ret, _, _ := procGMSE.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return 0, 0
	}
	return ms.TotalPhys, ms.AvailPhys
}

// readFDs returns approximate handle usage on Windows.
// Windows uses handles instead of FDs — the limit is effectively ~16M.
func readFDs() (used int, limit int) {
	limit = 16_000_000 // Windows handle limit is rarely a bottleneck

	h := windows.CurrentProcess()
	var count uint32
	ret, _, _ := procGetPHC.Call(uintptr(h), uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return 0, limit
	}
	return int(count), limit
}

// readCgroupCPUs returns 0 on Windows — no cgroup support.
func readCgroupCPUs() float64 {
	return 0
}

// readCPU returns process CPU time via GetProcessTimes.
func readCPU() cpuSample {
	h := windows.CurrentProcess()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return cpuSample{}
	}
	// FILETIME is in 100-nanosecond intervals
	return cpuSample{
		user:   filetimeToNanos(user),
		system: filetimeToNanos(kernel),
	}
}

func filetimeToNanos(ft windows.Filetime) uint64 {
	return (uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)) * 100
}
