// Package prereq runs pd-agent's startup preflight: warm up the embedded
// headless browser and warn on Windows if Defender exclusions aren't set.
//
// All ProjectDiscovery scanners (nuclei, naabu, httpx, dnsx, tlsx) are linked
// into the pd-agent binary via pkg/runtools. Service-version detection is
// handled natively by naabu's nmap-service-probes parser, so there are no
// external tool dependencies left to manage.
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

// EnsureAll runs the agent's startup preflight: warm up the headless browser
// and (on Windows) check Defender exclusions. Returns a list of components
// the agent couldn't validate — non-empty means the caller should exit.
// Today only browser warmup can land in that list; the Defender check is
// warn-only.
func EnsureAll() (failed []string) {
	if err := warmupBrowser(); err != nil {
		failed = append(failed, "browser (Chrome)")
	}

	CheckDefenderExclusions()

	return failed
}

// warmupBrowser validates the embedded headless browser by running an httpx
// screenshot probe against a loopback server. Surfaces missing Chrome shared
// libraries as a clear startup error instead of a mid-scan failure.
//
// First-launch Chrome download is ~150MB, hence the generous timeouts.
// Success is verified by stat'ing the screenshot file: httpx emits a Result
// record even when the screenshot itself timed out, so the JSON line alone
// is unreliable.
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
			slog.Error("prereq: browser validation failed — missing Chrome dependencies",
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
