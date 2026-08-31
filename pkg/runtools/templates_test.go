package runtools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// stubTemplates points nuclei's config at a temp dir and swaps the network and
// installer hooks, then restores everything on cleanup.
func stubTemplates(t *testing.T, version string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "nuclei-templates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir template dir: %v", err)
	}

	prevDir := config.DefaultConfig.TemplatesDirectory
	prevVersion := config.DefaultConfig.TemplateVersion
	prevLatest := config.DefaultConfig.LatestNucleiTemplatesVersion
	prevFetch, prevUpdate, prevFresh, prevNow := fetchLatestTag, incrementalUpdate, freshInstall, nowFn

	config.DefaultConfig.TemplatesDirectory = dir
	config.DefaultConfig.TemplateVersion = version
	resetLatestTagCache()

	t.Cleanup(func() {
		config.DefaultConfig.TemplatesDirectory = prevDir
		config.DefaultConfig.TemplateVersion = prevVersion
		config.DefaultConfig.LatestNucleiTemplatesVersion = prevLatest
		fetchLatestTag, incrementalUpdate, freshInstall, nowFn = prevFetch, prevUpdate, prevFresh, prevNow
		resetLatestTagCache()
	})

	return dir
}

func resetLatestTagCache() {
	latestTagMu.Lock()
	defer latestTagMu.Unlock()
	latestTag, latestTagAt, latestTagTry, latestTagErr = "", time.Time{}, time.Time{}, nil
}

func writeTemplate(t *testing.T, dir, rel string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte("id: test\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
}

func TestMissingTemplates(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/cves/2026/CVE-2026-1.yaml")

	absent := filepath.Join(t.TempDir(), "private", "priv.yaml")
	writeTemplate(t, filepath.Dir(absent), "priv.yaml")

	required := []string{
		"http/cves/2026/CVE-2026-1.yaml", // present
		"http/cves/2026/CVE-2026-2.yaml", // missing
		"http/cves/2025/CVE-2025-9.yaml", // missing
		absent,                           // absolute: private template, not ours to verify
		"",                               // ignored
	}

	got := MissingTemplates(required)
	want := []string{"http/cves/2026/CVE-2026-2.yaml", "http/cves/2025/CVE-2025-9.yaml"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("MissingTemplates() = %v, want %v", got, want)
	}
}

// A private template living outside the public dir must never trigger a repair.
func TestMissingTemplatesIgnoresAbsolutePaths(t *testing.T) {
	stubTemplates(t, "v10.4.8")
	if got := MissingTemplates([]string{"/tmp/pd-agent-priv-x/my-check.yaml"}); got != nil {
		t.Errorf("MissingTemplates() = %v, want nil for absolute paths", got)
	}
}

func TestLatestTemplateTagCaches(t *testing.T) {
	stubTemplates(t, "v10.4.5")

	calls := 0
	fetchLatestTag = func(context.Context) (string, error) {
		calls++
		return "v10.4.8", nil
	}
	base := time.Now()
	nowFn = func() time.Time { return base }

	for range 3 {
		tag, err := LatestTemplateTag(context.Background())
		if err != nil {
			t.Fatalf("LatestTemplateTag: %v", err)
		}
		if tag != "v10.4.8" {
			t.Fatalf("tag = %q, want v10.4.8", tag)
		}
	}
	if calls != 1 {
		t.Errorf("fetches = %d, want 1 within the TTL", calls)
	}

	nowFn = func() time.Time { return base.Add(latestTagTTL + time.Second) }
	if _, err := LatestTemplateTag(context.Background()); err != nil {
		t.Fatalf("LatestTemplateTag after TTL: %v", err)
	}
	if calls != 2 {
		t.Errorf("fetches = %d, want 2 after the TTL expires", calls)
	}
}

func TestLatestTemplateTagError(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("no network") }

	_, err := LatestTemplateTag(context.Background())
	if err == nil {
		t.Fatal("expected an error when the release API is unreachable")
	}
	if !errors.Is(err, ErrFreshnessUnknown) {
		t.Errorf("err = %v, want it to wrap ErrFreshnessUnknown", err)
	}
}

// Without caching failures a rate-limited fleet retries on every scan and keeps
// its own quota exhausted.
func TestLatestTemplateTagCachesFailures(t *testing.T) {
	stubTemplates(t, "v10.4.5")

	calls := 0
	fetchLatestTag = func(context.Context) (string, error) {
		calls++
		return "", errors.New("api down")
	}
	base := time.Now()
	nowFn = func() time.Time { return base }

	for range 3 {
		if _, err := LatestTemplateTag(context.Background()); err == nil {
			t.Fatal("expected the failure to surface")
		}
	}
	if calls != 1 {
		t.Errorf("fetches = %d, want 1 within the failure TTL", calls)
	}

	nowFn = func() time.Time { return base.Add(latestTagFailTTL + time.Second) }
	if _, err := LatestTemplateTag(context.Background()); err == nil {
		t.Fatal("expected the failure to surface after the TTL")
	}
	if calls != 2 {
		t.Errorf("fetches = %d, want 2 after the failure TTL expires", calls)
	}
}

// A transient outage must not pin the agent to the cached failure.
func TestLatestTemplateTagRecoversAfterFailure(t *testing.T) {
	stubTemplates(t, "v10.4.5")

	fail := true
	fetchLatestTag = func(context.Context) (string, error) {
		if fail {
			return "", errors.New("api down")
		}
		return "v10.4.8", nil
	}
	base := time.Now()
	nowFn = func() time.Time { return base }

	if _, err := LatestTemplateTag(context.Background()); err == nil {
		t.Fatal("expected the first lookup to fail")
	}

	fail = false
	nowFn = func() time.Time { return base.Add(latestTagFailTTL + time.Second) }
	tag, err := LatestTemplateTag(context.Background())
	if err != nil {
		t.Fatalf("LatestTemplateTag after recovery: %v", err)
	}
	if tag != "v10.4.8" {
		t.Errorf("tag = %q, want v10.4.8", tag)
	}
}

// stubLatestURL points the release lookup at a test server for one test.
func stubLatestURL(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	prev := templatesLatestURL
	templatesLatestURL = srv.URL
	t.Cleanup(func() {
		templatesLatestURL = prev
		srv.Close()
	})
}

func serveTag(tag string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": tag})
	}
}

func TestFetchLatestTagFromGitHub(t *testing.T) {
	t.Setenv(envconfig.KeyGitHubToken, "")

	var gotAuth string
	stubLatestURL(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		serveTag("v10.4.8")(w, r)
	})

	tag, err := fetchLatestTagFromGitHub(context.Background())
	if err != nil {
		t.Fatalf("fetchLatestTagFromGitHub: %v", err)
	}
	if tag != "v10.4.8" {
		t.Errorf("tag = %q, want v10.4.8", tag)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want none when no token is set", gotAuth)
	}
}

// The lookup must spend the same token the downloads already use, or an
// authenticated agent still burns the 60/hr unauthenticated per-IP budget.
func TestFetchLatestTagFromGitHubSendsToken(t *testing.T) {
	t.Setenv(envconfig.KeyGitHubToken, "ghp_example")

	var gotAuth string
	stubLatestURL(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		serveTag("v10.4.8")(w, r)
	})

	if _, err := fetchLatestTagFromGitHub(context.Background()); err != nil {
		t.Fatalf("fetchLatestTagFromGitHub: %v", err)
	}
	if gotAuth != "Bearer ghp_example" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer ghp_example")
	}
}

// The lookup gates agent startup, so it must never run on a client that can
// hang forever. http.DefaultClient has no timeout.
func TestLatestTagClientHasTimeout(t *testing.T) {
	if latestTagClient.Timeout == 0 {
		t.Fatal("latestTagClient has no timeout; a stalled connection would hang boot")
	}
}

func rateLimitedHandler(reset time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
	}
}

func TestFetchLatestTagFromGitHubRateLimited(t *testing.T) {
	t.Setenv(envconfig.KeyGitHubToken, "")
	stubLatestURL(t, rateLimitedHandler(time.Now().Add(20*time.Minute)))

	_, err := fetchLatestTagFromGitHub(context.Background())
	if !errors.Is(err, ErrGitHubRateLimited) {
		t.Fatalf("err = %v, want ErrGitHubRateLimited", err)
	}
	if !strings.Contains(err.Error(), envconfig.KeyGitHubToken) {
		t.Errorf("err = %q, want it to name %s as the fix", err, envconfig.KeyGitHubToken)
	}
	if !strings.Contains(err.Error(), "resets in") {
		t.Errorf("err = %q, want the reset window", err)
	}
}

// With a token already set, telling the operator to set one is useless advice.
func TestFetchLatestTagFromGitHubRateLimitedWithToken(t *testing.T) {
	t.Setenv(envconfig.KeyGitHubToken, "ghp_example")
	stubLatestURL(t, rateLimitedHandler(time.Now().Add(20*time.Minute)))

	_, err := fetchLatestTagFromGitHub(context.Background())
	if !errors.Is(err, ErrGitHubRateLimited) {
		t.Fatalf("err = %v, want ErrGitHubRateLimited", err)
	}
	if !strings.Contains(err.Error(), "also exhausted") {
		t.Errorf("err = %q, want it to say the configured token is exhausted", err)
	}
}

// A bad token also answers 403; only quota exhaustion sets Remaining: 0, and
// the two need opposite advice.
func TestFetchLatestTagFromGitHubForbiddenIsNotRateLimit(t *testing.T) {
	t.Setenv(envconfig.KeyGitHubToken, "ghp_bad")
	stubLatestURL(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "59")
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := fetchLatestTagFromGitHub(context.Background())
	if err == nil {
		t.Fatal("expected an error for 403")
	}
	if errors.Is(err, ErrGitHubRateLimited) {
		t.Errorf("err = %v, want a plain status error, not a rate-limit diagnosis", err)
	}
}

// The bug this whole change exists for: installed version behind the newest
// release must trigger an update, no matter what nuclei cached.
func TestEnsureLatestTemplatesUpdatesWhenBehind(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	// Nuclei's stale cache claiming we are current must not be believed.
	config.DefaultConfig.LatestNucleiTemplatesVersion = "v10.4.5"

	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	updated := false
	incrementalUpdate = func() error {
		updated = true
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return nil
	}
	freshInstall = func() error { t.Fatal("reinstall must not run when the update succeeds"); return nil }

	from, to, err := EnsureLatestTemplates(context.Background())
	if err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	if !updated {
		t.Error("incremental update never ran despite being 3 releases behind")
	}
	if from != "v10.4.5" || to != "v10.4.8" {
		t.Errorf("versions = %s -> %s, want v10.4.5 -> v10.4.8", from, to)
	}
}

func TestEnsureLatestTemplatesNoopWhenCurrent(t *testing.T) {
	stubTemplates(t, "v10.4.8")
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	incrementalUpdate = func() error { t.Fatal("update must not run when already current"); return nil }
	freshInstall = func() error { t.Fatal("reinstall must not run when already current"); return nil }

	from, to, err := EnsureLatestTemplates(context.Background())
	if err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	if from != to || to != "v10.4.8" {
		t.Errorf("versions = %s -> %s, want no change at v10.4.8", from, to)
	}
}

// An update that reports success but leaves the version behind is a lie; fall
// back to a full reinstall rather than trusting it.
func TestEnsureLatestTemplatesReinstallsWhenUpdateDoesNotLand(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	incrementalUpdate = func() error { return nil } // claims success, changes nothing
	reinstalled := false
	freshInstall = func() error {
		reinstalled = true
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return nil
	}

	if _, to, err := EnsureLatestTemplates(context.Background()); err != nil || to != "v10.4.8" {
		t.Fatalf("EnsureLatestTemplates = %q, %v; want v10.4.8, nil", to, err)
	}
	if !reinstalled {
		t.Error("expected a reinstall when the update did not land")
	}
}

func TestEnsureLatestTemplatesInstallsWhenDirMissing(t *testing.T) {
	dir := stubTemplates(t, "")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove dir: %v", err)
	}
	fetchLatestTag = func(context.Context) (string, error) {
		t.Fatal("must not need the release API to install a missing dir")
		return "", nil
	}
	installed := false
	freshInstall = func() error {
		installed = true
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return os.MkdirAll(dir, 0o755)
	}

	if _, to, err := EnsureLatestTemplates(context.Background()); err != nil || to != "v10.4.8" {
		t.Fatalf("EnsureLatestTemplates = %q, %v; want v10.4.8, nil", to, err)
	}
	if !installed {
		t.Error("expected a fresh install for a missing template dir")
	}
}

func TestEnsureLatestTemplatesPropagatesTagFailure(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("api down") }
	incrementalUpdate = func() error { t.Fatal("must not update blind"); return nil }
	freshInstall = func() error { t.Fatal("must not reinstall blind"); return nil }

	from, _, err := EnsureLatestTemplates(context.Background())
	if err == nil {
		t.Fatal("expected the release-API failure to surface")
	}
	// ensureNucleiTemplates keys off both of these to warn-and-continue rather
	// than ground an agent whose templates are already on disk.
	if !errors.Is(err, ErrFreshnessUnknown) {
		t.Errorf("err = %v, want it to wrap ErrFreshnessUnknown", err)
	}
	if from != "v10.4.5" {
		t.Errorf("from = %q, want the installed version so the caller can tell templates exist", from)
	}
}

// The case that produced the bad scan: version current, files absent.
func TestEnsureTemplatesForRepairsMissingFiles(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	required := []string{"http/cves/2026/CVE-2026-49049.yaml", "http/cves/2025/CVE-2025-54988.yaml"}

	freshInstall = func() error {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for _, rel := range required {
			full := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(full, []byte("id: x\n"), 0o600); err != nil {
				return err
			}
		}
		return nil
	}

	missing, err := EnsureTemplatesFor(context.Background(), required)
	if err != nil {
		t.Fatalf("EnsureTemplatesFor: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("missing after repair = %v, want none", missing)
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("%s still absent after repair", rel)
		}
	}
}

func TestEnsureTemplatesForSkipsRepairWhenComplete(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/cves/2026/CVE-2026-1.yaml")

	freshInstall = func() error { t.Fatal("must not reinstall when every template is present"); return nil }

	missing, err := EnsureTemplatesFor(context.Background(), []string{"http/cves/2026/CVE-2026-1.yaml"})
	if err != nil || len(missing) != 0 {
		t.Fatalf("EnsureTemplatesFor = %v, %v; want none, nil", missing, err)
	}
}

// A template the release genuinely does not carry must be reported, not hidden.
func TestEnsureTemplatesForReportsStillMissing(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	freshInstall = func() error { return os.MkdirAll(dir, 0o755) }

	missing, err := EnsureTemplatesFor(context.Background(), []string{"http/cves/2099/CVE-2099-1.yaml"})
	if err == nil {
		t.Fatal("expected an error when templates are absent after a reinstall")
	}
	if len(missing) != 1 || missing[0] != "http/cves/2099/CVE-2099-1.yaml" {
		t.Errorf("missing = %v, want the one absent path", missing)
	}
}

func TestReinstallTemplatesRestoresOnFailure(t *testing.T) {
	dir := stubTemplates(t, "v10.4.5")
	writeTemplate(t, dir, "http/keep-me.yaml")

	freshInstall = func() error { return errors.New("download failed") }

	if err := reinstallTemplates(); err == nil {
		t.Fatal("expected the download failure to surface")
	}
	// A failed repair must not leave the agent with zero templates.
	if _, err := os.Stat(filepath.Join(dir, "http/keep-me.yaml")); err != nil {
		t.Errorf("existing templates were lost on a failed reinstall: %v", err)
	}
	entries, _ := filepath.Glob(dir + ".stale-*")
	if len(entries) != 0 {
		t.Errorf("stale dir left behind: %v", entries)
	}
}

func TestSafeToReplace(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}

	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{name: "normal path", dir: filepath.Join(home, "nuclei-templates")},
		{name: "empty", dir: "", wantErr: true},
		{name: "relative", dir: "nuclei-templates", wantErr: true},
		{name: "root", dir: string(filepath.Separator), wantErr: true},
		{name: "home itself", dir: home, wantErr: true},
		{name: "top level", dir: string(filepath.Separator) + "templates", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := safeToReplace(tt.dir); (err != nil) != tt.wantErr {
				t.Errorf("safeToReplace(%q) error = %v, wantErr %v", tt.dir, err, tt.wantErr)
			}
		})
	}
}

// A tag resolved minutes ago still beats no comparison at all, so an outage
// must not throw it away.
func TestLatestTemplateTagKeepsLastKnownTagOnFailure(t *testing.T) {
	stubTemplates(t, "v10.4.5")

	base := time.Now()
	nowFn = func() time.Time { return base }
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	if _, err := LatestTemplateTag(context.Background()); err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	nowFn = func() time.Time { return base.Add(latestTagTTL + time.Second) }
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("api down") }
	if _, err := LatestTemplateTag(context.Background()); err == nil {
		t.Fatal("expected the failure to surface rather than a stale tag posing as fresh")
	}

	tag, at := LastKnownTemplateTag()
	if tag != "v10.4.8" {
		t.Errorf("LastKnownTemplateTag() = %q, want the retained v10.4.8", tag)
	}
	if !at.Equal(base) {
		t.Errorf("resolved-at = %v, want the original success time %v", at, base)
	}
}

// With the release API down, an agent must still update toward the last known
// release instead of standing still.
func TestEnsureLatestTemplatesFallsBackToLastKnownTag(t *testing.T) {
	stubTemplates(t, "v10.4.5")

	base := time.Now()
	nowFn = func() time.Time { return base }
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	if _, err := LatestTemplateTag(context.Background()); err != nil {
		t.Fatalf("seed lookup: %v", err)
	}

	nowFn = func() time.Time { return base.Add(latestTagTTL + latestTagFailTTL + time.Second) }
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("api down") }
	incrementalUpdate = func() error {
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return nil
	}
	freshInstall = func() error { t.Fatal("must not reinstall when the incremental update works"); return nil }

	from, to, err := EnsureLatestTemplates(context.Background())
	if err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	if from != "v10.4.5" || to != "v10.4.8" {
		t.Errorf("versions = %s -> %s, want v10.4.5 -> v10.4.8 via the last known tag", from, to)
	}
}

// No lookup has ever succeeded, so there is nothing to fall back to.
func TestEnsureLatestTemplatesFailsWithoutAnyKnownTag(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("api down") }
	incrementalUpdate = func() error { t.Fatal("must not update blind"); return nil }
	freshInstall = func() error { t.Fatal("must not reinstall blind"); return nil }

	if _, _, err := EnsureLatestTemplates(context.Background()); !errors.Is(err, ErrFreshnessUnknown) {
		t.Fatalf("err = %v, want ErrFreshnessUnknown", err)
	}
}

// Secondary rate limits answer with Retry-After and leave X-RateLimit-Remaining
// alone, so keying only on Remaining misses them.
func TestFetchLatestTagFromGitHubSecondaryRateLimit(t *testing.T) {
	t.Setenv(envconfig.KeyGitHubToken, "")
	stubLatestURL(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := fetchLatestTagFromGitHub(context.Background())
	if !errors.Is(err, ErrGitHubRateLimited) {
		t.Fatalf("err = %v, want ErrGitHubRateLimited", err)
	}
	if !strings.Contains(err.Error(), "retry after 60s") {
		t.Errorf("err = %q, want the Retry-After window", err)
	}
}
