// Package selfupdate handles downloading a new pd-agent binary from GitHub
// releases and replacing the running binary via rename + syscall.Exec.
package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/tidwall/gjson"
)

// PreflightEnvVar is set on the new binary's environment during a self-update
// preflight. The new binary should exit 0 cleanly soon after parsing flags
// (and any other safe init that does not touch shared state). Callers use
// this to detect "binary won't even start with the current args" before
// committing to swap, so a broken update does not brick the agent.
const PreflightEnvVar = "PDCP_PREFLIGHT"

const (
	githubRepo      = "projectdiscovery/pd-agent"
	binaryName      = "pd-agent"
	httpTimeout     = 60 * time.Second
	maxDownloadSize = 500 * 1024 * 1024 // 500 MB
	maxAPIResponse  = 10 * 1024 * 1024  // 10 MB
)

var httpClient = &http.Client{Timeout: httpTimeout}

// UpdateRequest is the payload from the NATS RPC update command.
type UpdateRequest struct {
	Version string `json:"version"` // e.g. "v1.2.3" or "latest"
}

// UpdateResult is returned to the caller before the process restarts.
type UpdateResult struct {
	AgentID        string `json:"agent_id"`
	Status         string `json:"status"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Message        string `json:"message,omitempty"`
}

// DownloadAndVerify resolves the requested version, downloads the binary from
// GitHub, and verifies it with -version. Returns the path to the verified temp
// binary. The caller is responsible for calling Apply or cleaning up the file.
//
// This phase is safe to run while the agent is still fully operational — no
// connections are drained, no work is interrupted.
//
// Set PDCP_UPDATE_URL to override the download URL (for local testing):
//
//	PDCP_UPDATE_URL=http://localhost:9999/pd-agent_2.0.0_macos_arm64.zip
func DownloadAndVerify(ctx context.Context, currentVersion, requestedVersion string) (string, error) {
	if IsContainer() {
		return "", fmt.Errorf("running in a container — update the image instead of self-updating")
	}

	targetVersion := requestedVersion
	downloadURL := ""
	var err error

	// Check for URL override (local testing / staging).
	if overrideURL := os.Getenv("PDCP_UPDATE_URL"); overrideURL != "" {
		downloadURL = overrideURL
		if targetVersion == "" || targetVersion == "latest" {
			targetVersion = "override"
		}
		slog.Info("selfupdate: using PDCP_UPDATE_URL override", "url", downloadURL)
	} else {
		// Resolve from GitHub releases.
		if requestedVersion == "latest" || requestedVersion == "" {
			targetVersion, downloadURL, err = resolveLatest()
		} else {
			downloadURL, err = resolveVersion(requestedVersion)
			targetVersion = requestedVersion
		}
		if err != nil {
			return "", fmt.Errorf("resolve version %s: %w", requestedVersion, err)
		}

		if currentVersion == targetVersion {
			return "", fmt.Errorf("already running %s", targetVersion)
		}
	}

	slog.Info("selfupdate: downloading", "version", targetVersion, "url", downloadURL)

	newBinary, err := downloadBinary(ctx, downloadURL)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}

	if err := verifyBinary(newBinary); err != nil {
		os.Remove(newBinary)
		return "", fmt.Errorf("verify: %w", err)
	}

	slog.Info("selfupdate: download and verify complete", "version", targetVersion, "path", newBinary)
	return newBinary, nil
}

// Prevalidate runs the new binary with the exact args Apply will exec with
// (current os.Args + injected --agent-id) and PDCP_PREFLIGHT=1 in the env.
// If the binary exits within preflightWindow, the update is aborted with the
// captured stderr so the running agent can keep serving instead of getting
// bricked.
//
// A binary that respects PreflightEnvVar exits 0 cleanly after flag parsing.
// Older binaries that do not honor the var either run normally (and would
// conflict with the live agent's NATS session) or die fast on flag mismatches.
// In both cases an early exit is treated as a failed preflight.
func Prevalidate(newBinaryPath, agentID string) error {
	const preflightWindow = 15 * time.Second

	args := ensureArg(os.Args, "--agent-id", agentID)
	if len(args) == 0 {
		return fmt.Errorf("preflight: empty restart args")
	}

	cmd := exec.Command(newBinaryPath, args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	cmd.Env = append(os.Environ(), PreflightEnvVar+"=1")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("preflight start: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		out := strings.TrimSpace(stderr.String())
		if err != nil {
			return fmt.Errorf("preflight: new binary exited early: %v (stderr: %s)", err, out)
		}
		return fmt.Errorf("preflight: new binary exited cleanly without honoring %s — likely an older build (stderr: %s)", PreflightEnvVar, out)
	case <-time.After(preflightWindow):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		slog.Info("selfupdate: preflight passed", "path", newBinaryPath, "window", preflightWindow)
		return nil
	}
}

// Apply replaces the running binary with the new one and restarts via
// syscall.Exec. Call this AFTER draining connections and in-flight work.
// agentID is injected into the restart args so the new process keeps the same ID.
//
// On success, this function does not return — the process is replaced.
// On failure, it returns an error and cleans up.
//
// The previous binary is left at execPath + ".old" so an operator can revert
// if the new binary turns out to be broken. CleanupOldBinary should be called
// from the new process after a startup-success milestone (e.g., NATS RPC up).
func Apply(newBinaryPath, currentVersion, agentID string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	// Replace: rename current → .old, move new → current.
	backupPath := execPath + ".old"
	if err := os.Rename(execPath, backupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := copyFile(newBinaryPath, execPath); err != nil {
		_ = os.Rename(backupPath, execPath) // rollback
		return fmt.Errorf("install new binary: %w", err)
	}

	if err := os.Chmod(execPath, 0755); err != nil {
		_ = os.Rename(backupPath, execPath) // rollback
		return fmt.Errorf("chmod: %w", err)
	}

	slog.Info("selfupdate: binary replaced, restarting", "path", execPath, "backup", backupPath, "agent_id", agentID)

	// Remove the temp source. Backup at execPath+".old" is intentionally kept
	// for recovery; CleanupOldBinary deletes it after the new process proves healthy.
	_ = os.Remove(newBinaryPath)

	// Build restart args: inject --agent-id so the new process keeps the same identity.
	args := ensureArg(os.Args, "--agent-id", agentID)

	// Exec replaces the current process with the new binary.
	// Same PID, same env, args with persisted agent ID.
	return syscall.Exec(execPath, args, os.Environ())
}

// CleanupOldBinary removes execPath+".old" if present. Call this from the
// running agent after it has reached a startup-success milestone (NATS up,
// agent registered) so a failed update can be recovered by booting from the
// backup until then.
func CleanupOldBinary() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return
	}
	backupPath := execPath + ".old"
	if _, err := os.Stat(backupPath); err != nil {
		return // nothing to clean up
	}
	if err := os.Remove(backupPath); err != nil {
		slog.Warn("selfupdate: failed to remove .old backup", "path", backupPath, "error", err)
		return
	}
	slog.Info("selfupdate: removed .old backup after successful startup", "path", backupPath)
}

// resolveLatest fetches the latest release tag and download URL from GitHub.
func resolveLatest() (version, downloadURL string, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github API %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	version = gjson.GetBytes(body, "tag_name").String()
	if version == "" {
		return "", "", fmt.Errorf("no tag_name in release")
	}

	downloadURL = findAssetURL(body)
	if downloadURL == "" {
		return "", "", fmt.Errorf("no matching asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	return version, downloadURL, nil
}

// resolveVersion fetches a specific release by tag and returns the download URL.
func resolveVersion(tag string) (downloadURL string, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", githubRepo, tag)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("fetch release %s: %w", tag, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API %d for tag %s", resp.StatusCode, tag)
	}

	downloadURL = findAssetURL(body)
	if downloadURL == "" {
		return "", fmt.Errorf("no matching asset for %s/%s in release %s", runtime.GOOS, runtime.GOARCH, tag)
	}

	return downloadURL, nil
}

// osName maps runtime.GOOS to the naming convention used in GitHub release assets.
func osName() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	default:
		return runtime.GOOS
	}
}

// findAssetURL searches release JSON for a zip matching the current OS/arch.
func findAssetURL(releaseJSON []byte) string {
	osArch := fmt.Sprintf("%s_%s", osName(), runtime.GOARCH)
	var url string

	gjson.GetBytes(releaseJSON, "assets").ForEach(func(_, asset gjson.Result) bool {
		name := strings.ToLower(asset.Get("name").String())
		if strings.Contains(name, binaryName) && strings.Contains(name, osArch) && strings.HasSuffix(name, ".zip") {
			url = asset.Get("browser_download_url").String()
			return false
		}
		return true
	})
	return url
}

// downloadBinary fetches a zip from the URL, extracts the binary, and returns
// the path to the extracted temp file.
func downloadBinary(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	// Save zip to temp file.
	tmpZip, err := os.CreateTemp("", "pd-agent-update-*.zip")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpZip.Name())

	if _, err := io.Copy(tmpZip, io.LimitReader(resp.Body, maxDownloadSize)); err != nil {
		tmpZip.Close()
		return "", err
	}
	tmpZip.Close()

	// Extract the binary from the zip.
	return extractBinaryFromZip(tmpZip.Name())
}

// extractBinaryFromZip opens a zip and extracts the pd-agent binary to a temp file.
func extractBinaryFromZip(zipPath string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name != binaryName && name != binaryName+".exe" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("open %s in zip: %w", name, err)
		}
		defer rc.Close()

		tmpBin, err := os.CreateTemp("", "pd-agent-new-*")
		if err != nil {
			return "", err
		}

		if _, err := io.Copy(tmpBin, rc); err != nil {
			tmpBin.Close()
			os.Remove(tmpBin.Name())
			return "", err
		}
		tmpBin.Close()

		if err := os.Chmod(tmpBin.Name(), 0755); err != nil {
			os.Remove(tmpBin.Name())
			return "", err
		}

		return tmpBin.Name(), nil
	}

	return "", fmt.Errorf("binary %s not found in zip", binaryName)
}

// verifyBinary runs the new binary with -version to check it's not corrupt.
// If the binary doesn't support -version (older versions), just check it's executable.
func verifyBinary(path string) error {
	cmd := exec.Command(path, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(output)
		// Older binaries don't have -version flag — that's OK, just means
		// we can't verify the version string. The binary is still valid.
		if strings.Contains(outStr, "flag provided but not defined") {
			slog.Warn("selfupdate: binary does not support -version (older version), skipping version check")
			return nil
		}
		return fmt.Errorf("binary failed -version check: %w (output: %s)", err, outStr)
	}
	slog.Info("selfupdate: verified new binary", "version", strings.TrimSpace(string(output)))
	return nil
}

// copyFile copies src to dst. Uses a temp file + rename for atomicity.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Write to temp file in same directory as dst (for atomic rename).
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".pd-agent-install-*")
	if err != nil {
		return err
	}

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()

	return os.Rename(tmp.Name(), dst)
}

// ensureArg adds or updates a --key=value arg in the args slice.
// If --key already exists (as --key=old or --key old), it's updated.
// If not, --key=value is appended.
func ensureArg(args []string, key, value string) []string {
	prefix := key + "="
	for i, arg := range args {
		if arg == key && i+1 < len(args) {
			// --key value (two separate args)
			result := make([]string, len(args))
			copy(result, args)
			result[i+1] = value
			return result
		}
		if strings.HasPrefix(arg, prefix) {
			// --key=value (single arg)
			result := make([]string, len(args))
			copy(result, args)
			result[i] = prefix + value
			return result
		}
	}
	// Not found — append.
	result := make([]string, len(args)+1)
	copy(result, args)
	result[len(args)] = prefix + value
	return result
}

// IsContainer checks if we're running inside a Docker/k8s container.
func IsContainer() bool {
	// Kubernetes injects this env var into every pod.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd") {
			return true
		}
	}
	// cgroup v2: check for container runtime in /proc/1/mountinfo
	data, err = os.ReadFile("/proc/self/mountinfo")
	if err == nil {
		s := string(data)
		if strings.Contains(s, "/docker/") || strings.Contains(s, "/kubepods/") {
			return true
		}
	}
	return false
}
