// Package prereq checks and installs the external tools that pd-agent depends
// on. It is designed to be idempotent: on restarts where every tool is already
// present, the cost is N exec.LookPath calls (microseconds, no network).
//
// Install strategy per tool kind:
//
//	PD tools  → go install (if Go available) → GitHub release binary download
//	System    → platform package manager (apt/brew) → warn if unavailable
//	Optional  → check only, log status, never block startup
package prereq

import (
	"archive/zip"
	"bufio"
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
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"github.com/tidwall/gjson"
)

// httpClient is used for all HTTP requests in this package.
// Timeout prevents hung startup if GitHub API or CDN is unreachable.
var httpClient = &http.Client{
	Timeout: 60 * time.Second,
}

const (
	// maxAPIResponseBytes limits GitHub API response reads (10 MB).
	maxAPIResponseBytes = 10 * 1024 * 1024
	// maxBinaryDownloadBytes limits binary download reads (500 MB).
	maxBinaryDownloadBytes = 500 * 1024 * 1024
)

// Priority controls whether a missing tool blocks agent startup.
type Priority int

const (
	Critical  Priority = iota // Agent cannot function — exit if install fails
	Important                 // Some features degrade — warn and continue
	Optional                  // Nice-to-have — log status only, never install
)

// Tool describes an external dependency.
type Tool struct {
	Name       string   // binary name (e.g. "nuclei")
	Priority   Priority // how hard we fail if missing
	GoInstall  string   // go install path (empty = not a Go tool)
	GitHubRepo string   // projectdiscovery/{repo} for binary download
	SystemPkg  PkgSpec  // platform package manager install info
	VersionArg string   // arg to get version (default "-version")
}

// PkgSpec describes how to install via system package managers.
type PkgSpec struct {
	Apt  string // apt package name (Linux)
	Brew string // brew formula name (macOS)
	// Windows: no system package manager, binary download only
}

// tools is the canonical list of agent prerequisites, derived from the
// Dockerfile runtime stage. Order matters — tools are checked/installed in
// this order.
var tools = []Tool{
	{
		Name:       "nuclei",
		Priority:   Critical,
		GoInstall:  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		GitHubRepo: "projectdiscovery/nuclei",
		VersionArg: "-version",
	},
	// naabu, httpx, dnsx, and tlsx are embedded via pkg/runtools — no install needed.
	{
		Name:     "nmap",
		Priority: Important,
		SystemPkg: PkgSpec{
			Apt:  "nmap",
			Brew: "nmap",
		},
		VersionArg: "--version",
	},
}

// Result holds the outcome of checking/installing a single tool.
type Result struct {
	Name      string
	Priority  Priority
	Found     bool
	Path      string
	Version   string
	Installed bool // true if we installed it this run
	Error     error
}

// EnsureAll checks every prerequisite and installs missing ones.
// Returns results for all tools and a list of critical tools that could not
// be resolved. If the returned failed list is non-empty, the agent should exit.
//
// Idempotency: if all tools are in PATH, this does N LookPath calls and
// returns immediately — no network, no disk writes, no subprocesses.
func EnsureAll() (results []Result, failed []string) {
	for _, t := range tools {
		r := check(t)

		if r.Found {
			slog.Info("prereq: found", "tool", t.Name, "path", r.Path, "version", r.Version)
			results = append(results, r)
			continue
		}

		// Optional tools: log and move on, never install.
		if t.Priority == Optional {
			slog.Info("prereq: optional tool not found", "tool", t.Name)
			results = append(results, r)
			continue
		}

		// Try to install.
		slog.Info("prereq: installing", "tool", t.Name)
		if err := install(t); err != nil {
			r.Error = err
			slog.Error("prereq: install failed", "tool", t.Name, "error", err)

			if t.Priority == Critical {
				failed = append(failed, t.Name)
			} else {
				slog.Warn("prereq: continuing without tool", "tool", t.Name)
			}
			results = append(results, r)
			continue
		}

		// Verify install worked.
		r = check(t)
		r.Installed = true
		if !r.Found {
			r.Error = fmt.Errorf("installed but not found in PATH")
			slog.Error("prereq: tool installed but not in PATH", "tool", t.Name,
				"hint", "check that GOPATH/bin or /usr/local/bin is in PATH")
			if t.Priority == Critical {
				failed = append(failed, t.Name)
			}
		} else {
			slog.Info("prereq: installed", "tool", t.Name, "path", r.Path, "version", r.Version)
		}
		results = append(results, r)
	}
	// Warm up the browser: run httpx with -screenshot against a known host.
	// This triggers Chrome download + validates shared library dependencies.
	// Idempotent — if Chrome is already cached, httpx exits in <2s.
	if err := warmupBrowser(); err != nil {
		failed = append(failed, "browser (Chrome)")
	}

	// Windows-only: warn loudly if Defender exclusions are missing.
	// No-op on Linux/macOS.
	CheckDefenderExclusions()

	return results, failed
}

// warmupBrowser runs an embedded httpx screenshot probe against a known host
// to trigger Chrome download (via go-rod) and validate that the browser starts
// — surfaces missing shared libraries as a clear startup error instead of a
// confusing mid-scan failure.
//
// First-time runs are slow because Chrome itself has to download (~150 MB) on
// first launch, so timeouts here are generous. We validate success by
// confirming an actual screenshot file landed on disk; the JSON Result alone
// is unreliable since httpx still emits a record (with screenshot_path set)
// even when the screenshot itself timed out.
func warmupBrowser() error {
	slog.Info("prereq: validating browser (embedded httpx screenshot probe)...")
	tmp, err := os.CreateTemp("", "httpx-warmup-*.jsonl")
	if err != nil {
		return fmt.Errorf("warmup tmp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	storeDir, err := os.MkdirTemp("", "httpx-warmup-store-*")
	if err != nil {
		return fmt.Errorf("warmup store dir: %w", err)
	}
	defer os.RemoveAll(storeDir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_, _, runErr := runtools.RunHttpx(ctx, []string{"www.example.com"}, runtools.HttpxOptions{
		OutputFile:        tmpPath,
		Screenshot:        true,
		Timeout:           20 * time.Second,
		ScreenshotTimeout: 90 * time.Second,
		DisableStdout:     true,
		StoreResponseDir:  storeDir,
	})
	if runErr != nil {
		msg := runErr.Error()
		if strings.Contains(msg, "cannot open shared object") ||
			strings.Contains(msg, "Failed to launch the browser") ||
			strings.Contains(msg, "error while loading shared libraries") {
			slog.Error("prereq: browser validation failed — missing Chrome dependencies",
				"error", msg,
				"hint", "install Chrome deps: sudo apt-get install -y libatk1.0-0 libatk-bridge2.0-0 libcups2 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 libnspr4 libnss3 libxcomposite1 libxfixes3 libxshmfence1 libxkbcommon0")
			return fmt.Errorf("missing Chrome shared libraries")
		}
		slog.Warn("prereq: browser validation httpx probe had non-fatal error", "error", msg)
	}

	// Confirm a screenshot file actually got written. httpx emits a JSON
	// record with screenshot_path even when the screenshot itself timed out,
	// so we have to read the path back and stat the file rather than trust
	// the JSON Result.
	if shotPath := readFirstScreenshotPath(tmpPath); shotPath != "" {
		if info, err := os.Stat(shotPath); err == nil && info.Size() > 0 {
			slog.Info("prereq: browser validation complete", "screenshot", shotPath)
			return nil
		}
	}

	slog.Error("prereq: browser validation failed — screenshot was not written",
		"hint", "Chrome may need more time on first launch (it downloads ~150MB); rerun, or pre-install Chrome via go-rod's manager")
	return fmt.Errorf("screenshot not produced")
}

// readFirstScreenshotPath parses the warmup output file and returns the
// screenshot_path of the first JSON Result line. Empty string if not found
// or unreadable; warmupBrowser treats that as a validation failure.
func readFirstScreenshotPath(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if shot := gjson.GetBytes(line, "screenshot_path").String(); shot != "" {
			return shot
		}
	}
	return ""
}

// check looks up a tool in PATH and optionally reads its version.
//
// If LookPath misses, falls back to probing the resolved install dir directly
// and adds it to PATH on hit. Handles the common case where the parent process
// (systemd unit, container CMD, etc.) doesn't include the install dir in PATH.
func check(t Tool) Result {
	r := Result{Name: t.Name, Priority: t.Priority}

	path, err := exec.LookPath(t.Name)
	if err != nil {
		binName := t.Name
		if runtime.GOOS == "windows" {
			binName += ".exe"
		}
		candidate := filepath.Join(resolveInstallDir(), binName)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			ensureInPath(filepath.Dir(candidate))
			path = candidate
		} else {
			return r
		}
	}
	r.Found = true
	r.Path = path

	// Best-effort version read — don't block on slow tools.
	if t.VersionArg != "" {
		out, err := exec.Command(path, t.VersionArg).CombinedOutput()
		if err == nil {
			// Take first line, trim noise.
			v := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			if len(v) > 100 {
				v = v[:100]
			}
			r.Version = v
		}
	}
	return r
}

// install tries platform-appropriate install methods in order.
func install(t Tool) error {
	// 1. Try go install (PD tools)
	if t.GoInstall != "" {
		if err := tryGoInstall(t); err == nil {
			return nil
		}
		// Fall through to binary download.
	}

	// 2. Try GitHub binary download (PD tools)
	if t.GitHubRepo != "" {
		if err := tryGitHubDownload(t); err == nil {
			return nil
		}
	}

	// 3. Try system package manager (nmap, etc.)
	if t.SystemPkg.Apt != "" || t.SystemPkg.Brew != "" {
		if err := trySystemInstall(t); err == nil {
			return nil
		}
	}

	return fmt.Errorf("all install methods exhausted for %s", t.Name)
}

// tryGoInstall runs `go install <path>` if Go is available.
func tryGoInstall(t Tool) error {
	goPath, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("go not in PATH")
	}
	slog.Info("prereq: trying go install", "tool", t.Name)
	cmd := exec.Command(goPath, "install", "-v", t.GoInstall)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install %s: %w", t.GoInstall, err)
	}
	return nil
}

// tryGitHubDownload fetches the latest release binary from GitHub.
func tryGitHubDownload(t Tool) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", t.GitHubRepo)
	slog.Info("prereq: trying GitHub download", "tool", t.Name, "repo", t.GitHubRepo)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes))
	if err != nil {
		return fmt.Errorf("read release: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github API %d", resp.StatusCode)
	}

	// Find matching asset: {tool}_{version}_{os}_{arch}.zip
	downloadURL := findAssetURL(body, t.Name, goos, goarch)
	if downloadURL == "" {
		return fmt.Errorf("no matching release asset for %s/%s", goos, goarch)
	}

	slog.Info("prereq: downloading", "tool", t.Name, "url", downloadURL)
	return downloadAndExtract(t.Name, downloadURL)
}

// findAssetURL searches GitHub release assets for a matching zip.
func findAssetURL(releaseJSON []byte, tool, goos, goarch string) string {
	// Primary pattern: {tool}_{version}_{os}_{arch}.zip
	osArch := fmt.Sprintf("%s_%s", goos, goarch)
	var url string

	gjson.GetBytes(releaseJSON, "assets").ForEach(func(_, asset gjson.Result) bool {
		name := strings.ToLower(asset.Get("name").String())
		if strings.Contains(name, tool) && strings.Contains(name, osArch) && strings.HasSuffix(name, ".zip") {
			url = asset.Get("browser_download_url").String()
			return false
		}
		return true
	})
	return url
}

// downloadAndExtract fetches a zip from url and extracts the tool binary.
func downloadAndExtract(tool, url string) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	tmpZip, err := os.CreateTemp("", tool+"-*.zip")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	defer os.Remove(tmpZip.Name())

	if _, err := io.Copy(tmpZip, io.LimitReader(resp.Body, maxBinaryDownloadBytes)); err != nil {
		tmpZip.Close()
		return fmt.Errorf("save: %w", err)
	}
	tmpZip.Close()

	installDir := resolveInstallDir()

	// Ensure install dir exists.
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", installDir, err)
	}

	if err := extractZip(tmpZip.Name(), tool, installDir); err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	binPath := filepath.Join(installDir, tool)
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if err := os.Chmod(binPath, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Ensure the install directory is in PATH so the post-install LookPath
	// verify succeeds. This also makes the tool available for the rest of
	// the agent's lifetime.
	ensureInPath(installDir)

	slog.Info("prereq: installed binary", "tool", tool, "path", binPath)
	return nil
}

// ensureInPath adds dir to the process PATH if it's not already there.
func ensureInPath(dir string) {
	pathEnv := os.Getenv("PATH")
	for _, p := range filepath.SplitList(pathEnv) {
		if p == dir {
			return // already in PATH
		}
	}
	os.Setenv("PATH", dir+string(os.PathListSeparator)+pathEnv)
	slog.Info("prereq: added to PATH", "dir", dir)
}

// resolveInstallDir picks the best bin directory for installing tools.
func resolveInstallDir() string {
	// Prefer GOPATH/bin (consistent with go install).
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		return filepath.Join(gopath, "bin")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "go", "bin")
	}
	return "/usr/local/bin"
}

// extractZip extracts files from a zip archive using Go's archive/zip stdlib.
// This avoids shelling out to unzip (Linux/macOS) or PowerShell (Windows),
// eliminating both the external dependency and command injection risks.
func extractZip(zipPath, binaryName, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		// Skip directories.
		if f.FileInfo().IsDir() {
			continue
		}

		// Flatten paths: extract only the base name (like unzip -j).
		name := filepath.Base(f.Name)

		// Guard against zip-slip: base name must not escape destDir.
		destPath := filepath.Join(destDir, name)
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if err := extractZipFile(f, destPath); err != nil {
			return fmt.Errorf("extract %s: %w", name, err)
		}
	}
	return nil
}

func extractZipFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}

// trySystemInstall uses the platform package manager for system tools.
func trySystemInstall(t Tool) error {
	switch runtime.GOOS {
	case "linux":
		return tryAptInstall(t)
	case "darwin":
		return tryBrewInstall(t)
	default:
		return fmt.Errorf("no system package manager for %s on %s", t.Name, runtime.GOOS)
	}
}

// tryAptInstall runs apt-get install for a tool (Linux).
// Only attempts installation when running as root or with passwordless sudo.
// Non-root users get a clear message instead of noisy permission errors.
func tryAptInstall(t Tool) error {
	if t.SystemPkg.Apt == "" {
		return fmt.Errorf("no apt package for %s", t.Name)
	}

	aptPath, err := exec.LookPath("apt-get")
	if err != nil {
		return fmt.Errorf("apt-get not found")
	}

	// Running as root (uid 0) — common in Docker containers.
	if os.Getuid() == 0 {
		slog.Info("prereq: apt-get install (root)", "tool", t.Name, "package", t.SystemPkg.Apt)
		cmd := exec.Command(aptPath, "install", "-y", t.SystemPkg.Apt)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Not root — don't attempt, just inform.
	return fmt.Errorf("apt-get requires root to install %s (run: sudo apt-get install -y %s)", t.Name, t.SystemPkg.Apt)
}

// tryBrewInstall runs brew install for a tool (macOS).
func tryBrewInstall(t Tool) error {
	if t.SystemPkg.Brew == "" {
		return fmt.Errorf("no brew formula for %s", t.Name)
	}

	brewPath, err := exec.LookPath("brew")
	if err != nil {
		return fmt.Errorf("brew not found")
	}

	slog.Info("prereq: trying brew install", "tool", t.Name, "formula", t.SystemPkg.Brew)
	cmd := exec.Command(brewPath, "install", t.SystemPkg.Brew)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
