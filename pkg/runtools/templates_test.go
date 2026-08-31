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
	prevFetch, prevFresh, prevNow := fetchLatestTag, freshInstall, nowFn
	prevWrite := writeTemplatesConfig
	writeTemplatesConfig = func() error { return nil }

	config.DefaultConfig.TemplatesDirectory = dir
	config.DefaultConfig.TemplateVersion = version
	resetLatestTagCache()

	t.Cleanup(func() {
		config.DefaultConfig.TemplatesDirectory = prevDir
		config.DefaultConfig.TemplateVersion = prevVersion
		config.DefaultConfig.LatestNucleiTemplatesVersion = prevLatest
		fetchLatestTag, freshInstall, nowFn = prevFetch, prevFresh, prevNow
		writeTemplatesConfig = prevWrite
		resetLatestTagCache()
	})

	return dir
}

func resetLatestTagCache() {
	latestTagMu.Lock()
	defer latestTagMu.Unlock()
	latestTag, latestTagAt, latestTagTry, latestTagErr = "", time.Time{}, time.Time{}, nil
	repairMu.Lock()
	repairWanted, repairReason, repairedAtVersion = false, "", ""
	repairMu.Unlock()
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
	installStub(t)
	download := freshInstall
	freshInstall = func() error {
		updated = true
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return download()
	}

	from, to, err := EnsureLatestTemplates(context.Background())
	if err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	if !updated {
		t.Error("no install ran despite being 3 releases behind")
	}
	if from != "v10.4.5" || to != "v10.4.8" {
		t.Errorf("versions = %s -> %s, want v10.4.5 -> v10.4.8", from, to)
	}
}

func TestEnsureLatestTemplatesNoopWhenCurrent(t *testing.T) {
	stubTemplates(t, "v10.4.8")
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	freshInstall = func() error { t.Fatal("nothing must install when already current"); return nil }

	from, to, err := EnsureLatestTemplates(context.Background())
	if err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	if from != to || to != "v10.4.8" {
		t.Errorf("versions = %s -> %s, want no change at v10.4.8", from, to)
	}
}

// An install that reports success but leaves the version behind is a lie, and
// must not be reported as an upgrade.
func TestEnsureLatestTemplatesFailsWhenInstallDoesNotLandTheVersion(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	installStub(t) // writes templates but never sets the version

	from, to, err := EnsureLatestTemplates(context.Background())
	if err == nil {
		t.Fatal("expected an error when the install did not reach the newest release")
	}
	if !strings.Contains(err.Error(), "v10.4.8") {
		t.Errorf("err = %v, want it to name the wanted release", err)
	}
	if from != "v10.4.5" || to != "v10.4.5" {
		t.Errorf("versions = %s -> %s, want both at v10.4.5", from, to)
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
	installStub(t)
	download := freshInstall
	freshInstall = func() error {
		installed = true
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return download()
	}

	if _, to, err := EnsureLatestTemplates(context.Background()); err != nil || to != "v10.4.8" {
		t.Fatalf("EnsureLatestTemplates = %q, %v; want v10.4.8, nil", to, err)
	}
	if !installed {
		t.Error("expected a fresh install for a missing template dir")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("template dir absent after the install: %v", err)
	}
}

func TestEnsureLatestTemplatesPropagatesTagFailure(t *testing.T) {
	stubTemplates(t, "v10.4.5")
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("api down") }
	freshInstall = func() error { t.Fatal("must not install blind"); return nil }

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
	installStub(t)
	download := freshInstall
	freshInstall = func() error {
		config.DefaultConfig.TemplateVersion = "v10.4.8"
		return download()
	}

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
	freshInstall = func() error { t.Fatal("must not install blind"); return nil }

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

// installStub fills the directory nuclei is pointed at, the way a real download
// does, and counts how many times it ran.
func installStub(t *testing.T, rels ...string) *int {
	t.Helper()
	calls := 0
	freshInstall = func() error {
		calls++
		dir := config.DefaultConfig.TemplatesDirectory
		for _, rel := range append([]string{"http/seed.yaml"}, rels...) {
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
	return &calls
}

func TestVerifyTemplatesForNeverInstalls(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/present.yaml")
	freshInstall = func() error { t.Fatal("chunk-scope verification must never install"); return nil }

	if got := VerifyTemplatesFor([]string{"http/present.yaml"}); got != nil {
		t.Errorf("VerifyTemplatesFor() = %v, want nil", got)
	}
	if got := VerifyTemplatesFor([]string{"http/absent.yaml"}); len(got) != 1 {
		t.Errorf("VerifyTemplatesFor() = %v, want the one missing path", got)
	}
}

// The regression the per-chunk installer caused: N chunks, N full reinstalls.
func TestChunkVerificationDoesNotAmplifyInstalls(t *testing.T) {
	stubTemplates(t, "v10.4.8")
	calls := installStub(t)

	for range 8 {
		missing := VerifyTemplatesFor([]string{"http/cves/2099/CVE-2099-1.yaml"})
		if len(missing) != 1 {
			t.Fatalf("missing = %v, want one", missing)
		}
		RequestTemplateRepair("test")
	}
	if *calls != 0 {
		t.Errorf("installs during chunk verification = %d, want 0", *calls)
	}

	// The queued repair runs once, at scan scope.
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }
	if _, _, err := EnsureLatestTemplates(context.Background()); err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	if *calls != 1 {
		t.Errorf("installs at scan scope = %d, want exactly 1", *calls)
	}
}

// Reinstalling the same release cannot produce a template it does not carry, so
// the attempt must not repeat until the release changes.
func TestRepairIsNotRetriedAtTheSameRelease(t *testing.T) {
	stubTemplates(t, "v10.4.8")
	calls := installStub(t)
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }

	RequestTemplateRepair("first")
	if _, _, err := EnsureLatestTemplates(context.Background()); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("installs = %d, want 1", *calls)
	}

	RequestTemplateRepair("second, same release")
	if _, _, err := EnsureLatestTemplates(context.Background()); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if *calls != 1 {
		t.Errorf("installs = %d, want the repair suppressed at the same release", *calls)
	}

	// A new release clears the suppression.
	config.DefaultConfig.TemplateVersion = "v10.4.9"
	RequestTemplateRepair("after a new release")
	if _, _, err := EnsureLatestTemplates(context.Background()); err != nil {
		t.Fatalf("third ensure: %v", err)
	}
	if *calls != 2 {
		t.Errorf("installs = %d, want a fresh attempt on the new release", *calls)
	}
}

// The live directory must hold a complete set at all times, never a half-written
// one, so the download lands in a sibling and is swapped in.
func TestInstallFreshSetDownloadsIntoStagingThenSwaps(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/old.yaml")

	var sawLiveDirDuringDownload bool
	freshInstall = func() error {
		staging := config.DefaultConfig.TemplatesDirectory
		if staging == dir {
			sawLiveDirDuringDownload = true
		}
		// The previous set must still be complete while the new one downloads.
		if _, err := os.Stat(filepath.Join(dir, "http/old.yaml")); err != nil {
			t.Errorf("live template set was disturbed during the download: %v", err)
		}
		full := filepath.Join(staging, "http/new.yaml")
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, []byte("id: x\n"), 0o600)
	}

	if err := installFreshSet(); err != nil {
		t.Fatalf("installFreshSet: %v", err)
	}
	if sawLiveDirDuringDownload {
		t.Error("download wrote straight into the live directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "http/new.yaml")); err != nil {
		t.Errorf("new set not swapped in: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "http/old.yaml")); err == nil {
		t.Error("old set still present; the swap should have replaced it")
	}
	for _, glob := range []string{dir + ".incoming-*", dir + ".retired-*"} {
		if leftovers, _ := filepath.Glob(glob); len(leftovers) != 0 {
			t.Errorf("leftover dir: %v", leftovers)
		}
	}
}

func TestInstallFreshSetKeepsWorkingSetOnFailure(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/keep-me.yaml")
	freshInstall = func() error { return errors.New("download failed") }

	if err := installFreshSet(); err == nil {
		t.Fatal("expected the download failure to surface")
	}
	if _, err := os.Stat(filepath.Join(dir, "http/keep-me.yaml")); err != nil {
		t.Errorf("working template set was lost on a failed download: %v", err)
	}
}

// An empty download must never replace a working set.
func TestInstallFreshSetRefusesEmptyDownload(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/keep-me.yaml")
	freshInstall = func() error { return os.MkdirAll(config.DefaultConfig.TemplatesDirectory, 0o755) }

	err := installFreshSet()
	if err == nil || !strings.Contains(err.Error(), "no templates") {
		t.Fatalf("err = %v, want a refusal to swap an empty set", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "http/keep-me.yaml")); err != nil {
		t.Errorf("working set was lost: %v", err)
	}
}

// The staging path must not survive in nuclei's config, or the next boot looks
// for a directory that was deleted.
func TestInstallFreshSetRestoresConfiguredPath(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	installStub(t)

	writes := 0
	writeTemplatesConfig = func() error {
		writes++
		if got := config.DefaultConfig.TemplatesDirectory; got != dir {
			t.Errorf("config written with %q, want the live path %q", got, dir)
		}
		return nil
	}

	if err := installFreshSet(); err != nil {
		t.Fatalf("installFreshSet: %v", err)
	}
	if writes == 0 {
		t.Error("nuclei's config was never rewritten with the live path")
	}
	if got := config.DefaultConfig.TemplatesDirectory; got != dir {
		t.Errorf("TemplatesDirectory left at %q, want %q", got, dir)
	}
}

// A template load holds the read lock; a repair must wait rather than swap the
// directory out from under it.
func TestRepairWaitsForAnInFlightTemplateLoad(t *testing.T) {
	stubTemplates(t, "v10.4.8")
	installStub(t)
	fetchLatestTag = func(context.Context) (string, error) { return "v10.4.8", nil }

	loading := make(chan struct{})
	released := make(chan struct{})
	go func() {
		templateRW.RLock() // stands in for RunNuclei's load phase
		close(loading)
		<-released
		templateRW.RUnlock()
	}()
	<-loading

	RequestTemplateRepair("test")
	done := make(chan struct{})
	go func() {
		_, _, _ = EnsureLatestTemplates(context.Background())
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("repair proceeded while a template load held the read lock")
	case <-time.After(100 * time.Millisecond):
	}

	close(released)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("repair never completed after the load finished")
	}
}

// Resolution must match what the scan will actually do, so it defers to nuclei's
// resolver instead of stat'ing paths.
func TestMissingTemplatesUsesNucleiResolver(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/cves/2024/CVE-2024-1.yaml")
	writeTemplate(t, dir, "http/cves/2024/CVE-2024-2.yaml")

	tests := []struct {
		name  string
		input string
		want  bool // reported missing
	}{
		{name: "literal present", input: "http/cves/2024/CVE-2024-1.yaml", want: false},
		{name: "literal absent", input: "http/cves/2024/CVE-2024-9.yaml", want: true},
		// Regression: the stat loop called this missing, hard-failing the chunk
		// and queueing a reinstall, while nuclei expands it to two templates.
		{name: "glob that matches", input: "http/cves/2024/*.yaml", want: false},
		{name: "glob with no match", input: "http/cves/2099/*.yaml", want: true},
		{name: "directory", input: "http/cves/2024", want: false},
		{name: "extensionless", input: "http/cves/2024/CVE-2024-1", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(missingTemplates([]string{tt.input})) > 0
			if got != tt.want {
				t.Errorf("missingTemplates(%q) missing = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMissingTemplatesPreservesInputOrderAndDedupes(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/present.yaml")

	got := missingTemplates([]string{"b.yaml", "http/present.yaml", "a.yaml", "b.yaml"})
	if strings.Join(got, ",") != "b.yaml,a.yaml" {
		t.Errorf("missingTemplates() = %v, want [b.yaml a.yaml]", got)
	}
}

// Reinstalling the public set cannot produce a private template, so an absent
// one must not queue a repair even though it is reported.
func TestAnyPublic(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  bool
	}{
		{name: "relative", input: []string{"http/x.yaml"}, want: true},
		{name: "absolute only", input: []string{"/tmp/pd-agent-priv-x/my-check.yaml"}, want: false},
		{name: "mixed", input: []string{"/tmp/priv/a.yaml", "http/x.yaml"}, want: true},
		{name: "empty", input: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AnyPublic(tt.input); got != tt.want {
				t.Errorf("AnyPublic(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// blockedByWriteLock reports whether fn waits while a staged install holds the
// write lock. An unlocked reader sees the repointed global mid-download and
// concludes every template is missing.
func blockedByWriteLock(t *testing.T, fn func()) bool {
	t.Helper()

	templateRW.Lock()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()

	blocked := false
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		blocked = true
	}
	templateRW.Unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("call never completed after the write lock was released")
	}
	return blocked
}

func TestVerifyTemplatesForTakesTheReadLock(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")
	writeTemplate(t, dir, "http/present.yaml")

	var missing []string
	if !blockedByWriteLock(t, func() { missing = VerifyTemplatesFor([]string{"http/present.yaml"}) }) {
		t.Error("VerifyTemplatesFor read the template dir during a staged install")
	}
	if len(missing) != 0 {
		t.Errorf("missing = %v, want none once the install finished", missing)
	}
}

func TestTemplateDirTakesTheReadLock(t *testing.T) {
	dir := stubTemplates(t, "v10.4.8")

	var got string
	if !blockedByWriteLock(t, func() { got = TemplateDir() }) {
		t.Error("TemplateDir read the global during a staged install")
	}
	if got != dir {
		t.Errorf("TemplateDir() = %q, want %q", got, dir)
	}
}
