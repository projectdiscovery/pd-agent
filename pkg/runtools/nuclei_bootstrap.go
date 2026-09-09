package runtools

import (
	"net/http"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	updateutils "github.com/projectdiscovery/utils/update"
)

// defaultHTTPCeiling is a hard cap on a whole exchange, body read included, not
// a stall guard: a download making steady progress is killed at the ceiling
// just the same. Sized for a ~150MB template zipball, where the stock 30s would
// need ~5MB/s sustained.
const defaultHTTPCeiling = 15 * time.Minute

var nucleiBootstrapOnce sync.Once

// InitNucleiProcess flips nuclei's package-level globals once. These are
// process-wide, so per-scan toggling risks a write race with concurrent scans.
// It also caps http.DefaultClient, which reaches every caller in this process
// that does not pass its own client, not just nuclei.
//
// Call it from the boot path, before any goroutine issues an HTTP request.
// Repeat calls are safe but only the first writes, and sync.Once orders callers
// against each other only: a first call from a scan goroutine would race every
// concurrent reader of http.DefaultClient.
func InitNucleiProcess() {
	nucleiBootstrapOnce.Do(func() {
		// Engine init runs UpdateIfOutdated, which writes the template directory
		// without taking templateRW. Disabling is one-way, so nothing may rely on
		// nuclei's updater afterwards.
		nuclei.DefaultConfig.DisableUpdateCheck()
		// Defaults to true upstream; pin in case that flips.
		installer.HideReleaseNotes = true

		// An install holds the template write lock, so a stalled download wedges
		// every scan behind it. updateutils picks one of two clients for the
		// zipball and each takes a different lever: without GITHUB_TOKEN it builds
		// its own, capped by DownloadUpdateTimeout; with one it discards that for
		// an oauth2 client that copies its timeout from http.DefaultClient.
		updateutils.DownloadUpdateTimeout = defaultHTTPCeiling
		http.DefaultClient.Timeout = defaultHTTPCeiling
	})
}
