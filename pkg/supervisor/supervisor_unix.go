//go:build !windows
// +build !windows

package supervisor

import (
	"context"
	"os"
	"syscall"

	"github.com/projectdiscovery/gologger"
)

// appendUnixSignals appends Unix-specific signals to the signals slice
func appendUnixSignals(signals []os.Signal) []os.Signal {
	return append(signals, syscall.SIGUSR1)
}

// handleUnixSignal handles Unix-specific signals
func handleUnixSignal(s *Supervisor, ctx context.Context, sig os.Signal) bool {
	if sig == syscall.SIGUSR1 {
		// Manual image update trigger (Unix only)
		gologger.Info().Msgf("Manual %s image update triggered", s.provider.Name())
		if err := s.Update(ctx); err != nil {
			gologger.Error().Msgf("Manual update failed: %v", err)
		}
		return true
	}
	return false
}

