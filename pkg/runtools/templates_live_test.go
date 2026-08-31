package runtools

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// TestEnsureLatestTemplatesLive exercises the real release lookup and the real
// installer against the machine's actual template directory. Opt-in: it reaches
// the network and rewrites ~/nuclei-templates.
//
//	PD_TEST_TEMPLATES_LIVE=1 go test ./pkg/runtools/ -run Live -v
func TestEnsureLatestTemplatesLive(t *testing.T) {
	if os.Getenv("PD_TEST_TEMPLATES_LIVE") != "1" {
		t.Skip("set PD_TEST_TEMPLATES_LIVE=1 to run against the real template dir")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	latest, err := LatestTemplateTag(ctx)
	if err != nil {
		t.Fatalf("LatestTemplateTag: %v", err)
	}
	t.Logf("template dir: %s", TemplateDir())
	t.Logf("installed:    %s", InstalledTemplateVersion())
	t.Logf("latest:       %s", latest)

	from, to, err := EnsureLatestTemplates(ctx)
	if err != nil {
		t.Fatalf("EnsureLatestTemplates: %v", err)
	}
	t.Logf("result:       %s -> %s", from, to)

	if to != latest {
		t.Errorf("installed version = %s after ensure, want %s", to, latest)
	}
}

// TestInstallFreshSetLive runs the real staged install against the machine's
// actual template directory: a full download into a sibling, then the swap.
// This is the path unit tests cannot cover, because stubbing the config writer
// is what keeps them from rewriting nuclei's real config file.
//
//	PD_TEST_TEMPLATES_LIVE=1 go test ./pkg/runtools/ -run InstallFreshSetLive -v
func TestInstallFreshSetLive(t *testing.T) {
	if os.Getenv("PD_TEST_TEMPLATES_LIVE") != "1" {
		t.Skip("set PD_TEST_TEMPLATES_LIVE=1 to run a real staged install")
	}

	dir := TemplateDir()
	before := countYAML(t, dir)
	t.Logf("before: %s at %s, %d templates", InstalledTemplateVersion(), dir, before)
	if before == 0 {
		t.Fatalf("no templates at %s; refusing to run", dir)
	}

	templateRW.Lock()
	err := installFreshSet()
	templateRW.Unlock()
	if err != nil {
		t.Fatalf("installFreshSet: %v", err)
	}

	after := countYAML(t, dir)
	t.Logf("after:  %s at %s, %d templates", InstalledTemplateVersion(), dir, after)
	if after == 0 {
		t.Fatal("template directory is empty after the swap")
	}
	if after < before/2 {
		t.Errorf("template count collapsed: %d -> %d", before, after)
	}

	// The staging path must not survive anywhere: not on disk, not in the config.
	for _, glob := range []string{dir + ".incoming-*", dir + ".retired-*"} {
		if leftovers, _ := filepath.Glob(glob); len(leftovers) != 0 {
			t.Errorf("leftover directory: %v", leftovers)
		}
	}
	if got := config.DefaultConfig.TemplatesDirectory; got != dir {
		t.Errorf("in-memory template dir = %q, want %q", got, dir)
	}
	configPath := filepath.Join(config.DefaultConfig.GetConfigDir(), ".templates-config.json")
	raw, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read %s: %v", configPath, readErr)
	}
	if strings.Contains(string(raw), ".incoming-") || strings.Contains(string(raw), ".retired-") {
		t.Errorf("%s still points at a temporary directory: %s", configPath, raw)
	}
	if !strings.Contains(string(raw), dir) {
		t.Errorf("%s lost the live template path %q: %s", configPath, dir, raw)
	}
}

func countYAML(t *testing.T, dir string) int {
	t.Helper()
	count := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yaml") {
			count++
		}
		return nil
	})
	return count
}
