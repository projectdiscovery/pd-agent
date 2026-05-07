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
// Keep this list in sync with prereq-windows.ps1.
var defenderTools = []string{
	"pd-agent.exe",
	"pd-agent-windows-amd64.exe",
	"pd-agent-windows-arm64.exe",
	"naabu.exe",
	"nuclei.exe",
	"httpx.exe",
	"dnsx.exe",
	"subfinder.exe",
	"katana.exe",
	"leakless.exe",
	"mapcidr.exe",
	"asnmap.exe",
	"tlsx.exe",
	"cdncheck.exe",
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
