//go:build windows

package prereq

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// defenderTools must be in Defender's exclusion list, otherwise real-time
// scanning quarantines them mid-run and the agent produces partial results.
// Keep in sync with prereq-windows.ps1.
var defenderTools = []string{
	"pd-agent.exe",
	"pd-agent-windows-amd64.exe",
	"pd-agent-windows-arm64.exe",
	"leakless.exe",
}

// CheckDefenderExclusions warns if pd-agent's bundled tools are not in the
// Defender exclusion list. Never blocks startup; silently skips when Defender
// is unreachable (third-party AV, Server Core, PS policy, ...).
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
	slog.Warn("WINDOWS DEFENDER EXCLUSIONS MISSING, SCANS WILL LIKELY FAIL")
	slog.Warn(bar)
	slog.Warn("These tools are NOT excluded from real-time scanning",
		"missing", strings.Join(missing, ", "))
	slog.Warn("Defender will quarantine them during scans, producing partial results.")
	slog.Warn("Fix once as Administrator:")
	slog.Warn("    powershell -ExecutionPolicy Bypass -File .\\prereq-windows.ps1")
	slog.Warn(bar)
}
