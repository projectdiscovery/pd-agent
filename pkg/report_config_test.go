package pkg

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
	"github.com/projectdiscovery/pd-agent/pkg/types"
)

const reportMarkerEnv = "PD_AGENT_REPORT_TEST_MARKER"
const reportMarkerValue = "host-env-marker-7f3a"

// recordingTracker stands in for a GitLab host and keeps the token of every
// API call it receives.
type recordingTracker struct {
	mu     sync.Mutex
	tokens []string
}

func (r *recordingTracker) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.tokens = append(r.tokens, req.Header.Get("PRIVATE-TOKEN"))
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if req.URL.Path == "/api/v4/user" {
		_, _ = fmt.Fprint(w, `{"id":1,"username":"pd-agent"}`)
		return
	}
	_, _ = fmt.Fprint(w, `{"id":1,"iid":1,"web_url":"http://tracker.invalid/1"}`)
}

func (r *recordingTracker) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tokens...)
}

// runScanWithReportConfig drives runNucleiScan with a reporting config that
// arrived in the work message, against a local target the template matches.
func runScanWithReportConfig(t *testing.T, reportConfig string) {
	t.Helper()
	// The engine otherwise fetches the latest templates release on its first run.
	nucleiconfig.DefaultConfig.DisableUpdateCheck()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "report-config-guard-match")
	}))
	t.Cleanup(target.Close)

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "report-config-guard.yaml")
	template := `id: report-config-guard
info:
  name: Report config guard
  author: pd
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - report-config-guard-match
`
	if err := os.WriteFile(templatePath, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	task := &types.Task{
		Tool: types.Nuclei,
		Id:   "chunk-report-guard",
		Options: types.Options{
			Hosts:        []string{target.URL},
			Templates:    []string{templatePath},
			ReportConfig: base64.StdEncoding.EncodeToString([]byte(reportConfig)),
			Output:       filepath.Join(dir, "out"),
		},
	}
	if _, _, err := runNucleiScan(context.Background(), task); err != nil {
		t.Fatalf("runNucleiScan: %v", err)
	}
}

func TestMessageReportConfigNeverExpandsHostEnv(t *testing.T) {
	t.Setenv(envconfig.KeyReportingConfig, "")
	t.Setenv(reportMarkerEnv, reportMarkerValue)

	tests := []struct {
		name  string
		token string
		// wantToken is the token the tracker must see; empty means the config
		// is refused and the tracker must see no request at all.
		wantToken string
	}{
		{
			name:      "literal token still reaches the tracker",
			token:     "literal-token",
			wantToken: "literal-token",
		},
		{
			name:  "env reference is refused",
			token: "$" + reportMarkerEnv,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := &recordingTracker{}
			srv := httptest.NewServer(tracker)
			t.Cleanup(srv.Close)

			cfg := fmt.Sprintf("gitlab:\n  base-url: %s/api/v4\n  username: pd-agent\n  token: %q\n  project-name: findings\n",
				srv.URL, tt.token)
			runScanWithReportConfig(t, cfg)

			tokens := tracker.seen()
			for _, tok := range tokens {
				if tok == reportMarkerValue {
					t.Fatalf("tracker received the agent host env value %s=%s from a work message config", reportMarkerEnv, reportMarkerValue)
				}
			}
			if tt.wantToken == "" {
				if len(tokens) != 0 {
					t.Fatalf("tracker received %d requests, want none for a refused config", len(tokens))
				}
				return
			}
			if len(tokens) == 0 || tokens[0] != tt.wantToken {
				t.Fatalf("tracker tokens = %v, want %q", tokens, tt.wantToken)
			}
		})
	}
}

func TestMessageReportConfigNeverWritesLocalFiles(t *testing.T) {
	t.Setenv(envconfig.KeyReportingConfig, "")

	tests := []struct {
		name string
		cfg  string
	}{
		{name: "markdown", cfg: "markdown:\n  directory: %q\n"},
		{name: "jsonl", cfg: "jsonl:\n  file: %q\n"},
		{name: "sarif", cfg: "sarif:\n  file: %q\n"},
		{name: "jsonl through a merge key", cfg: "<<: {jsonl: {file: %q}}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exportDir := filepath.Join(t.TempDir(), "export")
			if err := os.MkdirAll(exportDir, 0o700); err != nil {
				t.Fatalf("create export dir: %v", err)
			}
			runScanWithReportConfig(t, fmt.Sprintf(tt.cfg, filepath.Join(exportDir, "planted")))
			var written []string
			_ = filepath.Walk(exportDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					written = append(written, path)
				}
				return nil
			})
			if len(written) > 0 {
				t.Fatalf("work message reporting config wrote files on the agent host: %v", written)
			}
		})
	}
}

func TestCheckMessageReportingConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr bool
	}{
		{name: "tracker with literal token", cfg: "jira:\n  url: https://example.atlassian.net\n  token: abc\n"},
		{name: "dollar inside a value", cfg: "jira:\n  token: abc$def\n"},
		{name: "env reference in tracker token", cfg: "jira:\n  token: $PDCP_API_KEY\n", wantErr: true},
		{name: "quoted env reference", cfg: "github:\n  token: \"$GITHUB_TOKEN\"\n", wantErr: true},
		{name: "list items are not expanded", cfg: "allow-list:\n  tags:\n    - $HOME\n"},
		{name: "jira custom field placeholder", cfg: "jira:\n  token: abc\n  custom-fields:\n    customfield_10000: $Severity\n"},
		{name: "env reference in a tracker url", cfg: "gitlab:\n  base-url: $HOME\n", wantErr: true},
		{name: "markdown exporter", cfg: "markdown:\n  directory: /tmp/x\n", wantErr: true},
		{name: "json exporter", cfg: "json:\n  file: /tmp/x\n", wantErr: true},
		{name: "pdf exporter", cfg: "pdf:\n  file: /tmp/x\n", wantErr: true},
		{name: "binary tag hides an env reference", cfg: "gitlab:\n  token: !!binary JFBEQ1BfQVBJX0tFWQ==\n", wantErr: true},
		{name: "local tag hides an env reference", cfg: "gitlab:\n  token: !x $PDCP_API_KEY\n", wantErr: true},
		{name: "merge key adds a file exporter", cfg: "<<: {jsonl: {file: /tmp/x}}\n", wantErr: true},
		{name: "alias key names a file exporter", cfg: "name: &k jsonl\n*k : {file: /tmp/x}\n", wantErr: true},
		{name: "not yaml", cfg: "jira: [", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkMessageReportingConfig([]byte(tt.cfg))
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkMessageReportingConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
