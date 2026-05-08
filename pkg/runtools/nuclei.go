package runtools

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

// UpdateNucleiTemplates installs nuclei-templates if missing, otherwise checks
// for updates and applies them. Replaces a `nuclei -update-templates` shell-out.
// Idempotent: safe to call at every agent startup.
func UpdateNucleiTemplates() error {
	tm := &installer.TemplateManager{}
	if err := tm.UpdateIfOutdated(); err != nil {
		return fmt.Errorf("update nuclei templates: %w", err)
	}
	return nil
}
