package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

const httpRetestTemplate = `id: retest-headers
info:
  name: retest headers
  author: pd
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "vulnerable-marker"
`

const headlessRetestTemplate = `id: retest-headless
info:
  name: retest headless
  author: pd
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}"
`

func TestRetestNeedsHeadless(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		template string
		want     bool
	}{
		{name: "http template", template: httpRetestTemplate, want: false},
		{name: "headless template", template: headlessRetestTemplate, want: true},
		{name: "unreadable template keeps headless on", template: "{not yaml", want: true},
		{name: "empty template keeps headless on", template: "", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, retestNeedsHeadless([]byte(tc.template)))
		})
	}
}

// An HTTP retest must run on a host with no browser that cannot download one,
// as on an isolated network. Set RETEST_NO_BROWSER_HOST=1 only where
// that holds (CI image or a container without chromium and without egress).
func TestHandleNucleiRetestHTTPWithoutBrowser(t *testing.T) {
	if os.Getenv("RETEST_NO_BROWSER_HOST") != "1" {
		t.Skip("needs a host without a browser and without internet; set RETEST_NO_BROWSER_HOST=1")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vulnerable-marker"))
	}))
	defer target.Close()

	req, err := json.Marshal(map[string]any{
		"targets":          []string{target.URL},
		"template_encoded": base64.StdEncoding.EncodeToString([]byte(httpRetestTemplate)),
	})
	require.NoError(t, err)

	r := &Runner{}
	got, err := r.handleNucleiRetest(context.Background(), "nuclei-retest", req)
	require.NoError(t, err)
	event, ok := got.(*output.ResultEvent)
	require.True(t, ok, "unexpected result type %T", got)
	require.True(t, event.MatcherStatus, "the marker is served, so the retest must match")
}
