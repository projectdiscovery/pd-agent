package runtools

import (
	"sync"

	"github.com/go-rod/rod/lib/launcher"
)

type chromeInfo struct {
	path string
	ok   bool
}

// resolveSystemChrome runs go-rod's LookPath once. Matching the check
// httpx/nuclei run internally means we never force "use installed" on a host
// that has none, which would hard-error instead of falling back to download.
var resolveSystemChrome = sync.OnceValue(func() chromeInfo {
	path, ok := launcher.LookPath()
	return chromeInfo{path: path, ok: ok}
})

// systemChromeAvailable reports whether a chrome/chromium binary is installed
// on this host. httpx and nuclei must be told to use it (go-rod ships no
// arm64-linux chrome to download); when absent, go-rod downloads its own,
// which only works on amd64.
func systemChromeAvailable() bool { return resolveSystemChrome().ok }

// SystemChromePath returns the resolved system browser path and whether one was
// found, so callers can log which browser the embedded scanners will use.
func SystemChromePath() (string, bool) {
	c := resolveSystemChrome()
	return c.path, c.ok
}
