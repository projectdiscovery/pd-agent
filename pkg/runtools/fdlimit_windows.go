//go:build windows

package runtools

// RaiseFileLimit is a no-op on Windows: no RLIMIT_NOFILE equivalent and
// per-process handle limits are already in the millions.
func RaiseFileLimit() {}
