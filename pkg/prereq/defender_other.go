//go:build !windows

package prereq

// CheckDefenderExclusions is a no-op on non-Windows platforms.
func CheckDefenderExclusions() {}
