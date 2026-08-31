package runtools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// templatesLatestURL is a var only so tests can point it at httptest.
var templatesLatestURL = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"

const (
	latestTagTTL     = 15 * time.Minute
	latestTagFailTTL = 2 * time.Minute
	latestTagTimeout = 30 * time.Second
)

// ErrFreshnessUnknown reports that the newest release could not be resolved.
// Templates already on disk are untouched and remain usable, so callers that
// only wanted an upgrade should log and continue rather than abort.
var ErrFreshnessUnknown = errors.New("nuclei-templates freshness could not be verified")

// ErrGitHubRateLimited is ErrFreshnessUnknown's actionable case: the request
// was rejected for quota, which GITHUB_TOKEN raises from 60/hr per IP to
// 5000/hr per token.
var ErrGitHubRateLimited = errors.New("github api rate limit exhausted")

// latestTagClient bounds the release lookup. http.DefaultClient has no
// timeout, and this call gates agent startup.
var latestTagClient = &http.Client{Timeout: latestTagTimeout}

// templateMu serializes every read-modify-write of the shared template
// directory: concurrent scans must not update and reinstall at once.
var templateMu sync.Mutex

var (
	latestTagMu sync.Mutex
	latestTag   string    // last tag resolved successfully
	latestTagAt time.Time // when latestTag was resolved
	// latestTagTry is the last attempt, successful or not. Separate from
	// latestTagAt so a retained stale tag is never served as if it were fresh.
	latestTagTry time.Time
	latestTagErr error
)

// Swappable for tests; the real ones download ~150MB or hit the network.
var (
	fetchLatestTag    = fetchLatestTagFromGitHub
	incrementalUpdate = func() error { return (&installer.TemplateManager{}).UpdateIfOutdated() }
	freshInstall      = func() error { return (&installer.TemplateManager{}).FreshInstallIfNotExists() }
	nowFn             = time.Now
)

// TemplateDir returns the directory nuclei loads public templates from.
func TemplateDir() string { return config.DefaultConfig.TemplatesDirectory }

// InstalledTemplateVersion returns the release nuclei recorded on disk. It is
// advisory only: the version can be current while files are missing.
func InstalledTemplateVersion() string { return config.DefaultConfig.TemplateVersion }

func fetchLatestTagFromGitHub(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, templatesLatestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// Same variable projectdiscovery/utils/update authenticates the template
	// downloads with, so one token covers lookup and download alike.
	if token := envconfig.GitHubToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := latestTagClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if isRateLimited(resp) {
		return "", fmt.Errorf("%w%s", ErrGitHubRateLimited, rateLimitAdvice(resp))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("releases/latest status %d", resp.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("releases/latest returned no tag_name")
	}
	return release.TagName, nil
}

// isRateLimited reports whether GitHub rejected the request for quota rather
// than for the credential being wrong: a 403 alone is also how a bad token
// reads, and the two need different advice.
func isRateLimited(resp *http.Response) bool {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return true
	}
	// Secondary limits leave X-RateLimit-Remaining untouched and answer with
	// Retry-After instead.
	return resp.Header.Get("Retry-After") != ""
}

// rateLimitAdvice names the fix and, when GitHub says so, when the quota returns.
func rateLimitAdvice(resp *http.Response) string {
	var b strings.Builder
	if sec, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		if wait := time.Until(time.Unix(sec, 0)); wait > 0 {
			fmt.Fprintf(&b, ", resets in %s", wait.Round(time.Second))
		}
	} else if retry := resp.Header.Get("Retry-After"); retry != "" {
		fmt.Fprintf(&b, ", retry after %ss", retry)
	}
	if envconfig.GitHubToken() == "" {
		fmt.Fprintf(&b, "; set %s to raise the limit from 60/hr per IP to 5000/hr", envconfig.KeyGitHubToken)
	} else {
		fmt.Fprintf(&b, "; the %s in use is also exhausted", envconfig.KeyGitHubToken)
	}
	return b.String()
}

// LatestTemplateTag returns the newest published nuclei-templates release,
// cached for latestTagTTL to stay inside the unauthenticated API quota.
// Deliberately not nuclei's cached "nuclei-templates-latest-version": the SDK
// refreshes that only after the code that could act on it has already run.
func LatestTemplateTag(ctx context.Context) (string, error) {
	latestTagMu.Lock()
	defer latestTagMu.Unlock()

	if latestTag != "" && nowFn().Sub(latestTagAt) < latestTagTTL {
		return latestTag, nil
	}
	// Cache failures too, briefly: without this a rate-limited fleet retries on
	// every scan and keeps its own quota exhausted.
	if latestTagErr != nil && nowFn().Sub(latestTagTry) < latestTagFailTTL {
		return "", latestTagErr
	}

	latestTagTry = nowFn()
	tag, err := fetchLatestTag(ctx)
	if err != nil {
		// latestTag is deliberately kept: a tag resolved minutes ago is still
		// the best comparison available, and callers may fall back to it.
		latestTagErr = fmt.Errorf("%w: %w", ErrFreshnessUnknown, err)
		return "", latestTagErr
	}
	latestTag, latestTagAt, latestTagErr = tag, nowFn(), nil
	return tag, nil
}

// LastKnownTemplateTag returns the most recent successfully resolved release
// and when it was resolved, so a caller can still compare versions while the
// release API is unreachable. Empty when no lookup has ever succeeded.
func LastKnownTemplateTag() (string, time.Time) {
	latestTagMu.Lock()
	defer latestTagMu.Unlock()
	return latestTag, latestTagAt
}

// MissingTemplates returns the repo-relative paths absent from the template
// directory. Absolute paths are skipped: private templates are materialized
// into a per-chunk temp dir and are not part of the public set.
func MissingTemplates(required []string) []string {
	dir := TemplateDir()
	if dir == "" {
		return nil
	}

	var missing []string
	for _, path := range required {
		if path == "" || filepath.IsAbs(path) {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
			missing = append(missing, path)
		}
	}
	return missing
}

// safeToReplace rejects template directories that would make removal
// catastrophic: a mistyped or empty config must never delete a home directory.
func safeToReplace(dir string) error {
	if dir == "" {
		return fmt.Errorf("template directory is unset")
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("template directory %q is not absolute", dir)
	}
	clean := filepath.Clean(dir)
	if clean == string(filepath.Separator) || clean == "." {
		return fmt.Errorf("refusing to replace %q", clean)
	}
	if home, err := os.UserHomeDir(); err == nil && clean == filepath.Clean(home) {
		return fmt.Errorf("refusing to replace the home directory %q", clean)
	}
	if len(strings.Split(strings.Trim(clean, string(filepath.Separator)), string(filepath.Separator))) < 2 {
		return fmt.Errorf("refusing to replace top-level path %q", clean)
	}
	return nil
}

// reinstallTemplates discards the template directory and downloads the current
// release. It is the only repair for a recorded version that is current while
// files are absent, and it runs regardless of nuclei's update-check flag
// (FreshInstallIfNotExists gates on directory existence, not that flag). The
// old directory moves aside first so a failed download leaves templates intact.
//
// Callers must hold templateMu.
func reinstallTemplates() error {
	dir := TemplateDir()
	if err := safeToReplace(dir); err != nil {
		return err
	}

	aside := dir + ".stale-" + strconv.Itoa(os.Getpid())
	_ = os.RemoveAll(aside)

	moved := false
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, aside); err != nil {
			return fmt.Errorf("move stale templates aside: %w", err)
		}
		moved = true
	}

	slog.Info("nuclei templates: reinstall started", "path", dir)
	start := nowFn()
	if err := freshInstall(); err != nil {
		if moved {
			_ = os.RemoveAll(dir)
			_ = os.Rename(aside, dir)
		}
		return fmt.Errorf("fresh install templates: %w", err)
	}
	if moved {
		_ = os.RemoveAll(aside)
	}
	slog.Info("nuclei templates: reinstall finished",
		"path", dir, "version", InstalledTemplateVersion(), "duration", nowFn().Sub(start))
	return nil
}

// EnsureLatestTemplates brings the template set to the newest published
// release, returning the versions before and after. A missing directory is
// installed; a lagging one is updated incrementally; an update that fails to
// land the expected version falls back to a full reinstall.
func EnsureLatestTemplates(ctx context.Context) (from, to string, err error) {
	templateMu.Lock()
	defer templateMu.Unlock()

	from = InstalledTemplateVersion()

	dir := TemplateDir()
	if dir == "" {
		return from, from, fmt.Errorf("could not determine nuclei template directory")
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		if err := freshInstall(); err != nil {
			return from, from, fmt.Errorf("install templates: %w", err)
		}
		return from, InstalledTemplateVersion(), nil
	}

	latest, err := LatestTemplateTag(ctx)
	if err != nil {
		stale, at := LastKnownTemplateTag()
		if stale == "" {
			return from, from, err
		}
		slog.Warn("nuclei templates: release lookup failed, comparing against the last known release",
			"release", stale, "resolved_ago", nowFn().Sub(at).Round(time.Second), "error", err)
		latest = stale
	}
	if from == latest {
		return from, latest, nil
	}

	// Hand nuclei the real latest version: its own cached value is what makes
	// NeedsTemplateUpdate report "current" while releases behind.
	config.DefaultConfig.LatestNucleiTemplatesVersion = latest

	slog.Info("nuclei templates: update started", "from", from, "to", latest)
	start := nowFn()
	if updateErr := incrementalUpdate(); updateErr != nil {
		slog.Warn("nuclei templates: incremental update failed, reinstalling",
			"from", from, "to", latest, "error", updateErr)
		if err := reinstallTemplates(); err != nil {
			return from, InstalledTemplateVersion(), err
		}
	} else if got := InstalledTemplateVersion(); got != latest {
		slog.Warn("nuclei templates: update did not land the expected version, reinstalling",
			"want", latest, "got", got)
		if err := reinstallTemplates(); err != nil {
			return from, InstalledTemplateVersion(), err
		}
	}

	to = InstalledTemplateVersion()
	if to != latest {
		return from, to, fmt.Errorf("templates still at %s after repair, want %s", to, latest)
	}
	slog.Info("nuclei templates: update finished", "from", from, "to", to, "duration", nowFn().Sub(start))
	return from, to, nil
}

// EnsureTemplatesFor guarantees every required public template is on disk.
// Version equality is not enough: a set at the newest release can still be
// missing files, and only a reinstall repairs that. Returns the paths still
// missing after the repair attempt.
func EnsureTemplatesFor(ctx context.Context, required []string) ([]string, error) {
	if missing := MissingTemplates(required); len(missing) == 0 {
		return nil, nil
	}

	templateMu.Lock()
	defer templateMu.Unlock()

	// Re-check under the lock: a concurrent chunk may have just repaired it.
	missing := MissingTemplates(required)
	if len(missing) == 0 {
		return nil, nil
	}

	slog.Warn("nuclei templates: requested templates missing, repairing",
		"missing_count", len(missing), "sample", sample(missing, 3),
		"installed_version", InstalledTemplateVersion())

	if err := reinstallTemplates(); err != nil {
		return missing, err
	}

	if stillMissing := MissingTemplates(required); len(stillMissing) > 0 {
		return stillMissing, fmt.Errorf("%d requested templates absent from %s after reinstall",
			len(stillMissing), InstalledTemplateVersion())
	}
	return nil, nil
}

func sample(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return items[:n]
}
