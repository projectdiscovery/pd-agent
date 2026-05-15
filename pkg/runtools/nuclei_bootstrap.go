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
		nuclei.DefaultConfig.DisableUpdateCheck()
		// Defaults to true upstream; pin in case that flips.
		installer.HideReleaseNotes = true
	})
}
