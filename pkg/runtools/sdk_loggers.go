package runtools

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// SilenceSDKLoggers swaps gologger's default writer for a discard sink.
// Several ProjectDiscovery SDKs (httpx, naabu) write per-result JSON or
// host:port lines to gologger.Silent() and don't honour their own
// DisableStdout options. pd-agent uses slog for its own output and doesn't
// rely on gologger anywhere meaningful, so muting it process-wide is safe.
// Call from main() once at startup, before any scanner SDK runs.
func SilenceSDKLoggers() {
	gologger.DefaultLogger.SetWriter(silentGologgerWriter{})
}

type silentGologgerWriter struct{}

func (silentGologgerWriter) Write(_ []byte, _ levels.Level) {}
