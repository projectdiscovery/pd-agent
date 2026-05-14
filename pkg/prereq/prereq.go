// Package prereq runs pd-agent's startup preflight: warm up the embedded
// headless browser and warn on Windows if Defender exclusions aren't set.
package prereq

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"github.com/tidwall/gjson"
)

// EnsureAll runs the startup preflight. The returned slice lists components
// that failed validation; non-empty means the caller should exit. The
// Defender check is warn-only and never lands here.
func EnsureAll() (failed []string) {
	if err := warmupBrowser(); err != nil {
		failed = append(failed, "browser (Chrome)")
	}

	CheckDefenderExclusions()

	return failed
}

// warmupBrowser validates the headless browser via an httpx screenshot probe
// against a loopback server, surfacing missing Chrome libs as a startup error.
// Success is verified by stat'ing the screenshot file because httpx emits a
// Result record even when the screenshot itself timed out.
func warmupBrowser() error {
	slog.Info("prereq: validating browser (embedded httpx screenshot probe)...")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h1>pd-agent warmup</h1></body></html>`))
	}))
	defer srv.Close()

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

	_, _, runErr := runtools.RunHttpx(ctx, []string{srv.URL}, runtools.HttpxOptions{
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
			slog.Error("prereq: browser validation failed, missing Chrome dependencies",
				"error", msg,
				"hint", "install Chrome deps: sudo apt-get install -y libatk1.0-0 libatk-bridge2.0-0 libcups2 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 libnspr4 libnss3 libxcomposite1 libxfixes3 libxshmfence1 libxkbcommon0")
			return fmt.Errorf("missing Chrome shared libraries")
		}
		slog.Warn("prereq: browser validation httpx probe had non-fatal error", "error", msg)
	}

	if shotPath := readFirstScreenshotPath(tmpPath); shotPath != "" {
		if info, err := os.Stat(shotPath); err == nil && info.Size() > 0 {
			slog.Info("prereq: browser validation complete")
			return nil
		}
	}

	slog.Error("prereq: browser validation failed, screenshot was not written",
		"hint", "Chrome may need more time on first launch (it downloads ~150MB); rerun, or pre-install Chrome via go-rod's manager")
	return fmt.Errorf("screenshot not produced")
}

// readFirstScreenshotPath returns the screenshot_path of the first JSON
// Result line; empty if not found or unreadable.
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
