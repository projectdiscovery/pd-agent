package runtools

import (
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"

	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

var nucleiBootstrapOnce sync.Once

// InitNucleiProcess flips nuclei's package-level globals once. These are
// process-wide, so per-scan toggling risks a write race with concurrent scans.
func InitNucleiProcess() {
	nucleiBootstrapOnce.Do(func() {
		// Engine init runs UpdateIfOutdated, which writes the shared template
		// directory without taking templateRW, so a concurrent chunk can load a
		// half-updated set and report a clean scan. Updates are ours: a staged
		// install under the write lock. Disabling is one-way, so nothing here
		// may rely on nuclei's updater afterwards.
		nuclei.DefaultConfig.DisableUpdateCheck()
		// Defaults to true upstream; pin in case that flips.
		installer.HideReleaseNotes = true
	})
}
