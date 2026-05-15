//go:build !windows

package runtools

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// RaiseFileLimit raises RLIMIT_NOFILE soft as high as the kernel accepts.
// On macOS rl.Max is often RLIM_INFINITY but setrlimit is capped by
// kern.maxfilesperproc, so probe a ladder of decreasing values.
func RaiseFileLimit() {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		slog.Warn("fdlimit: getrlimit failed", "error", err)
		return
	}
	before := rl.Cur

	targets := []uint64{rl.Max, 1 << 20, 1 << 18, 1 << 17, 1 << 16}
	for _, t := range targets {
		rl.Cur = t
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rl); err == nil {
			slog.Info("fdlimit: raised RLIMIT_NOFILE", "before", before, "after", t)
			return
		}
	}
	slog.Warn("fdlimit: all setrlimit attempts failed, leaving as-is", "soft", before)
}
