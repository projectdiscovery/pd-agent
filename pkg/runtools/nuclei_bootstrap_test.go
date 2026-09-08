package runtools

import (
	"context"
	"net/http"
	"testing"

	updateutils "github.com/projectdiscovery/utils/update"
	"golang.org/x/oauth2"
)

// An install holds the template write lock, so an unbounded download wedges
// every scan behind it. updateutils picks a different client depending on
// whether GITHUB_TOKEN is set, so both levers have to be capped.
func TestInitNucleiProcessCapsBothDownloadPaths(t *testing.T) {
	InitNucleiProcess()

	// Without a token, updateutils builds its own client from this var.
	if updateutils.DownloadUpdateTimeout != defaultHTTPCeiling {
		t.Errorf("DownloadUpdateTimeout = %s, want %s", updateutils.DownloadUpdateTimeout, defaultHTTPCeiling)
	}

	// With one, it discards that client for an oauth2 client. Construct it the
	// same way updateutils does and assert the timeout survives: this pins the
	// upstream behaviour the cap relies on, which asserting on
	// http.DefaultClient alone would not catch if x/oauth2 stopped copying it.
	c := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "x"}))
	if c.Timeout != defaultHTTPCeiling {
		t.Errorf("oauth2 client timeout = %s, want %s inherited from http.DefaultClient", c.Timeout, defaultHTTPCeiling)
	}
	if http.DefaultClient.Timeout != defaultHTTPCeiling {
		t.Errorf("http.DefaultClient timeout = %s, want %s", http.DefaultClient.Timeout, defaultHTTPCeiling)
	}
}
