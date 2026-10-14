package runtools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunNucleiCancellationStopsRateLimitWait(t *testing.T) {
	firstRequest := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		select {
		case firstRequest <- struct{}{}:
		default:
		}
		_, _ = fmt.Fprint(writer, "ok")
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "rate-limit-cancellation.yaml")
	template := `id: rate-limit-cancellation
info:
  name: Rate limit cancellation
  author: pd
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/?value={{value}}"
    payloads:
      value:
        - one
        - two
`
	if err := os.WriteFile(templatePath, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := RunNuclei(ctx, NucleiOptions{
			OutputFile:           filepath.Join(dir, "results.jsonl"),
			Targets:              []string{server.URL},
			Templates:            []string{templatePath},
			AllowLocalFileAccess: true,
			ConfigYAML:           []byte("rate-limit: 1\n"),
		})
		result <- err
	}()

	select {
	case <-firstRequest:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("nuclei did not execute the first request")
	}

	cancelledAt := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunNuclei error = %v, want context cancellation", err)
		}
		if delay := time.Since(cancelledAt); delay >= 500*time.Millisecond {
			t.Fatalf("RunNuclei returned %s after cancellation, want under 500ms", delay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunNuclei remained blocked after cancellation")
	}
}
