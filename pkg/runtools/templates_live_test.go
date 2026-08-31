package runtools

import (
	"context"
	"os"
	"testing"
	"time"
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
