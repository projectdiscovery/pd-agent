//go:build windows

package prereq

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// defenderTools lists process names that must be in Microsoft Defender's
// exclusion list. Without exclusions, real-time scanning quarantines them
// mid-scan and the agent silently produces partial/empty results.
//
// After the SDK-embed migration, all PD scanners (nuclei/naabu/httpx/dnsx/
// tlsx) live inside pd-agent.exe — they no longer exist as standalone
// processes. The only externally-spawned binary still in scope is leakless,
// which go-rod extracts to a per-launch temp dir to supervise Chrome.
// Keep this list in sync with prereq-windows.ps1.
var defenderTools = []string{
	"pd-agent.exe",
	"pd-agent-windows-amd64.exe",
	"pd-agent-windows-arm64.exe",
	"leakless.exe",
}

// CheckDefenderExclusions verifies pd-agent's bundled tools are excluded from
// Defender real-time scanning. Soft check — never blocks startup, only warns.
// Skips silently if Defender isn't reachable (third-party AV, Server Core,
// PowerShell policy blocked, etc.) since we can't make any claim then.
func CheckDefenderExclusions() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive",
		"-Command", "Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess").Output()
	if err != nil {
		slog.Debug("prereq: defender check skipped (Defender not reachable)", "error", err)
		return
	}

	excluded := strings.ToLower(string(out))
	var missing []string
	for _, name := range defenderTools {
		if !strings.Contains(excluded, strings.ToLower(name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		slog.Info("prereq: defender exclusions present", "checked", len(defenderTools))
		return
	}

	bar := strings.Repeat("=", 78)
	slog.Warn(bar)
	slog.Warn("WINDOWS DEFENDER EXCLUSIONS MISSING — SCANS WILL LIKELY FAIL")
	slog.Warn(bar)
	slog.Warn("These tools are NOT excluded from real-time scanning",
		"missing", strings.Join(missing, ", "))
	slog.Warn("Defender will quarantine them during scans, producing partial results.")
	slog.Warn("Fix once as Administrator:")
	slog.Warn("    powershell -ExecutionPolicy Bypass -File .\\prereq-windows.ps1")
	slog.Warn(bar)
}
