package runtools

import (
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

var nucleiBootstrapOnce sync.Once

// InitNucleiProcess flips nuclei's package-level globals once. These are
// process-wide, so per-scan toggling is wasted work and risks a write race
// when the first concurrent scans fire.
func InitNucleiProcess() {
	nucleiBootstrapOnce.Do(func() {
		nuclei.DefaultConfig.DisableUpdateCheck()

		// Defaults to true upstream, set explicitly so a future default
		// flip in nuclei/pkg/installer doesn't surprise us.
		installer.HideReleaseNotes = true
	})
}
