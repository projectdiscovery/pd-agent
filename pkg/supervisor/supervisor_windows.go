//go:build windows
// +build windows

package supervisor

import (
	"context"
	"os"
)

// appendUnixSignals appends Unix-specific signals to the signals slice
// On Windows, this is a no-op
func appendUnixSignals(signals []os.Signal) []os.Signal {
	return signals
}

// handleUnixSignal handles Unix-specific signals
// On Windows, this always returns false
func handleUnixSignal(s *Supervisor, ctx context.Context, sig os.Signal) bool {
	return false
}

