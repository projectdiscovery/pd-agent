package runtools

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// SilenceSDKLoggers routes gologger output to a discard sink. httpx and naabu
// SDKs write per-result lines via gologger.Silent() and ignore their own
// DisableStdout options. Call once at startup before any scanner runs.
func SilenceSDKLoggers() {
	gologger.DefaultLogger.SetWriter(silentGologgerWriter{})
}

type silentGologgerWriter struct{}

func (silentGologgerWriter) Write(_ []byte, _ levels.Level) {}
