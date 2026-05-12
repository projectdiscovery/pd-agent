package runtools

import (
	"os"
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

var nucleiBootstrapOnce sync.Once

// InitNucleiProcess sets nuclei's process-global flags once. Idempotent.
// Call this from main() before any RunNuclei invocation; repeats are no-ops.
//
// Why: these flags live on package-level globals inside nuclei and its
// installer / runner subpackages. Toggling them per scan is wasted work and
// risks a write race when the first concurrent scans fire.
func InitNucleiProcess() {
	nucleiBootstrapOnce.Do(func() {
		// Mutate config.DefaultConfig once. Per-scan calls to
		// nuclei.DisableUpdateCheck() did this redundantly.
		nuclei.DefaultConfig.DisableUpdateCheck()

		// Already true by default in nuclei/pkg/installer, but set it
		// explicitly so a future default flip upstream doesn't surprise us.
		installer.HideReleaseNotes = true

		// Suppress the "configure your PDCP API key from ..." warning that
		// nuclei prints when SetupPDCPUpload runs without creds.
		// nuclei's runner.HideAutoSaveMsg lives in an internal package we
		// can't import; it reads DISABLE_CLOUD_UPLOAD_WRN at module init,
		// so the env var is the only handle we have. Safe to set even when
		// PDCP_API_KEY is populated — the warning only fires on a no-creds
		// SetupPDCPUpload path, which already shouldn't happen for agents.
		_ = os.Setenv("DISABLE_CLOUD_UPLOAD_WRN", "true")
	})
}
