package runtools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
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

// templateRW guards the shared template directory. Repairs and updates take
// the write lock; nuclei takes the read lock while loading templates, so a
// swap can never land mid-load and hand a scan a partial set.
var templateRW sync.RWMutex

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
	fetchLatestTag       = fetchLatestTagFromGitHub
	freshInstall         = func() error { return (&installer.TemplateManager{}).FreshInstallIfNotExists() }
	writeTemplatesConfig = func() error { return config.DefaultConfig.WriteTemplatesConfig() }
	nowFn                = time.Now
)

// TemplateDir returns the directory nuclei loads public templates from. It
// takes the read lock: a staged install repoints this global while it downloads,
// so an unlocked reader can see a path that is about to be deleted.
func TemplateDir() string {
	templateRW.RLock()
	defer templateRW.RUnlock()
	return templateDir()
}

// templateDir reads the global without locking, for callers already holding
// templateRW.
func templateDir() string { return config.DefaultConfig.TemplatesDirectory }

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

// missingTemplates returns the requested definitions nuclei cannot resolve. It
// defers to nuclei's own resolver rather than stat'ing paths: the resolver globs,
// walks directories and resolves relative paths, so a stat loop reports a glob
// entry as missing while the scan expands it happily.
func missingTemplates(required []string) []string {
	dir := templateDir()
	if dir == "" || len(required) == 0 {
		return nil
	}

	_, errs := disk.NewCatalog(dir).GetTemplatesPath(required)
	if len(errs) == 0 {
		return nil
	}

	// Walk the input, not the map: map order is random and these paths reach
	// logs and error messages.
	missing := make([]string, 0, len(errs))
	seen := make(map[string]struct{}, len(errs))
	for _, def := range required {
		if _, bad := errs[def]; !bad {
			continue
		}
		if _, dup := seen[def]; dup {
			continue
		}
		seen[def] = struct{}{}
		missing = append(missing, def)
	}
	return missing
}

// AnyPublic reports whether any definition belongs to the shared template
// directory. Private templates are absolute paths in a per-chunk temp dir, and
// reinstalling the public set cannot conjure one of those.
func AnyPublic(definitions []string) bool {
	for _, def := range definitions {
		if def != "" && !filepath.IsAbs(def) {
			return true
		}
	}
	return false
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

// downloadInto installs the current release into staging. FreshInstallIfNotExists
// has no per-call directory, so nuclei's configured path is pointed at staging
// for the download. WriteTemplatesConfig marshals the whole config, so the real
// path is written back afterwards or the next boot would look for staging.
func downloadInto(staging string) error {
	live := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.TemplatesDirectory = staging
	installErr := freshInstall()
	config.DefaultConfig.TemplatesDirectory = live

	if err := writeTemplatesConfig(); err != nil {
		slog.Warn("nuclei templates: could not restore the template path in nuclei's config",
			"path", live, "error", err)
	}
	if installErr != nil {
		return fmt.Errorf("download templates: %w", installErr)
	}
	if !dirHasTemplates(staging) {
		return fmt.Errorf("downloaded set at %s contains no templates", staging)
	}
	return nil
}

// dirHasTemplates reports whether dir holds at least one template, so an empty
// download is never swapped over a working set.
func dirHasTemplates(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// installFreshSet downloads the current release into a sibling directory and
// swaps it in. Downloading in place would leave the live directory half-written
// for the length of the download; here it is only ever replaced by a complete
// set, and the previous set is kept until the swap succeeds.
//
// Callers must hold templateRW for writing.
func installFreshSet() error {
	dir := templateDir()
	if err := safeToReplace(dir); err != nil {
		return err
	}

	pid := strconv.Itoa(os.Getpid())
	staging, retired := dir+".incoming-"+pid, dir+".retired-"+pid
	_ = os.RemoveAll(staging)
	_ = os.RemoveAll(retired)
	defer func() {
		_ = os.RemoveAll(staging)
		_ = os.RemoveAll(retired)
	}()

	slog.Info("nuclei templates: download started", "staging", staging)
	start := nowFn()
	if err := downloadInto(staging); err != nil {
		return err
	}

	moved := false
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, retired); err != nil {
			return fmt.Errorf("retire the previous template set: %w", err)
		}
		moved = true
	}
	if err := os.Rename(staging, dir); err != nil {
		if moved {
			if restoreErr := os.Rename(retired, dir); restoreErr != nil {
				slog.Error("nuclei templates: no template set on disk, restore failed",
					"path", dir, "retired", retired, "error", restoreErr)
			}
		}
		return fmt.Errorf("swap the new template set into place: %w", err)
	}

	slog.Info("nuclei templates: download finished",
		"path", dir, "version", InstalledTemplateVersion(), "duration", nowFn().Sub(start))
	return nil
}

var (
	repairMu          sync.Mutex
	repairWanted      bool
	repairReason      string
	repairedAtVersion string
)

// RequestTemplateRepair marks the on-disk set as suspect so the next scan-level
// refresh reinstalls it before any chunk runs. A repair already attempted at the
// current release is not retried: reinstalling the same release cannot produce a
// template that release does not contain.
func RequestTemplateRepair(reason string) {
	repairMu.Lock()
	defer repairMu.Unlock()

	if installed := InstalledTemplateVersion(); installed != "" && installed == repairedAtVersion {
		slog.Debug("nuclei templates: repair already attempted at this release, not retrying",
			"version", installed, "reason", reason)
		return
	}
	if !repairWanted {
		slog.Warn("nuclei templates: repair queued for the next scan", "reason", reason)
	}
	repairWanted, repairReason = true, reason
}

func takeRepairRequest() (string, bool) {
	repairMu.Lock()
	defer repairMu.Unlock()
	return repairReason, repairWanted
}

func markRepaired() {
	repairMu.Lock()
	defer repairMu.Unlock()
	repairWanted, repairReason = false, ""
	repairedAtVersion = InstalledTemplateVersion()
}

// EnsureLatestTemplates brings the template set to the newest published
// release, returning the versions before and after. A missing directory is
// installed; a lagging one is updated incrementally; an update that fails to
// land the expected version falls back to a full reinstall.
func EnsureLatestTemplates(ctx context.Context) (from, to string, err error) {
	templateRW.Lock()
	defer templateRW.Unlock()

	from = InstalledTemplateVersion()

	dir := templateDir()
	if dir == "" {
		return from, from, fmt.Errorf("could not determine nuclei template directory")
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		if err := installFreshSet(); err != nil {
			return from, from, fmt.Errorf("install templates: %w", err)
		}
		return from, InstalledTemplateVersion(), nil
	}

	if reason, wanted := takeRepairRequest(); wanted {
		slog.Warn("nuclei templates: reinstalling before the scan", "reason", reason)
		if err := installFreshSet(); err != nil {
			return from, InstalledTemplateVersion(), err
		}
		markRepaired()
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

	// A staged install is the only writer: nuclei's own incremental update is
	// disabled process-wide because it writes the directory without taking this
	// lock. A full install measures ~6s, so there is nothing to gain from it.
	slog.Info("nuclei templates: update started", "from", from, "to", latest)
	start := nowFn()
	if err := installFreshSet(); err != nil {
		return from, InstalledTemplateVersion(), err
	}

	to = InstalledTemplateVersion()
	if to != latest {
		return from, to, fmt.Errorf("templates still at %s after repair, want %s", to, latest)
	}
	slog.Info("nuclei templates: update finished", "from", from, "to", to, "duration", nowFn().Sub(start))
	return from, to, nil
}

// VerifyTemplatesFor returns the requested public templates missing from disk.
// It never installs: repairs belong at scan scope, before chunks launch, so a
// bad set cannot have every chunk re-downloading the shared directory.
func VerifyTemplatesFor(required []string) []string {
	templateRW.RLock()
	defer templateRW.RUnlock()
	return missingTemplates(required)
}
