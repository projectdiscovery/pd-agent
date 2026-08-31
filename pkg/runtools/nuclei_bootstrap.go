package runtools

import (
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

var nucleiBootstrapOnce sync.Once

// InitNucleiProcess flips nuclei's package-level globals once. These are
// process-wide, so per-scan toggling risks a write race with concurrent scans.
func InitNucleiProcess() {
	nucleiBootstrapOnce.Do(func() {
		// DisableUpdateCheck() is deliberately NOT called: it is a one-way
		// process-global that short-circuits NeedsTemplateUpdate(), which
		// silently pinned agents to whatever release they booted with.
		// Defaults to true upstream; pin in case that flips.
		installer.HideReleaseNotes = true
	})
}
