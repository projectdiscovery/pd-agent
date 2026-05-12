//go:build windows

package runtools

// RaiseFileLimit is a no-op on Windows. There is no RLIMIT_NOFILE equivalent;
// Go's os.Open uses CreateFileW directly (no CRT stdio cap), and per-process
// kernel handle limits sit in the millions.
func RaiseFileLimit() {}
