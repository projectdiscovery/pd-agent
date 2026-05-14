package runtools

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

// HttpxOptions configures an embedded httpx scan. Exposes only the fields
// pd-agent actually drives; defaults match the CLI for everything else.
type HttpxOptions struct {
	// OutputFile receives one JSON Result per line. Required.
	OutputFile string
	// Concurrency is the worker count. Defaults to 50 (matches CLI default).
	Concurrency int
	// Timeout per probe. Defaults to 5s.
	Timeout time.Duration
	// Screenshot enables headless Chrome screenshot capture per result.
	Screenshot bool
	// ScreenshotTimeout bounds each headless screenshot. Defaults to 10s
	// (matches CLI default), but first-time runs need longer because Chrome
	// itself has to download.
	ScreenshotTimeout time.Duration
	// DisableStdout suppresses httpx's per-result stdout writes. Output still
	// lands in OutputFile; callers that don't want JSON spilling into the
	// agent log should set this.
	DisableStdout bool
	// StoreResponseDir overrides where stored responses + screenshots land.
	// Empty falls through to httpx's default ("output" in cwd).
	StoreResponseDir string
}

// RunHttpx probes every target and writes one JSON Result per line to
// opts.OutputFile (matching `httpx -json -irr -o`). Returns the output file
// path and the list of resolved URLs from successful probes — callers can use
// the URL slice to feed the next pipeline step without re-parsing the file.
func RunHttpx(ctx context.Context, targets []string, opts HttpxOptions) (string, []string, error) {
	if opts.OutputFile == "" {
		return "", nil, errors.New("RunHttpx: OutputFile is required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 50
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.ScreenshotTimeout <= 0 {
		opts.ScreenshotTimeout = 10 * time.Second
	}

	var (
		mu   sync.Mutex
		urls []string
	)
	httpxOpts := &runner.Options{
		InputTargetHost:    goflags.StringSlice(targets),
		Output:             opts.OutputFile,
		JSONOutput:         true,
		ResponseInStdout:   true, // -irr equivalent
		Silent:             true,
		Threads:            opts.Concurrency,
		Timeout:            int(opts.Timeout.Seconds()),
		Screenshot:         opts.Screenshot,
		ScreenshotTimeout:  opts.ScreenshotTimeout,
		DisableStdout:      opts.DisableStdout,
		StoreResponseDir:   opts.StoreResponseDir,
		StatusCode:         true,
		FollowRedirects:    true,
		MaxRedirects:       10,
		DisableUpdateCheck: true,
		Probe:              true,
		OnResult: func(r runner.Result) {
			if r.Err != nil || r.URL == "" {
				return
			}
			mu.Lock()
			urls = append(urls, r.URL)
			mu.Unlock()
		},
	}

	if err := httpxOpts.ValidateOptions(); err != nil {
		return "", nil, fmt.Errorf("validate httpx options: %w", err)
	}

	r, err := runner.New(httpxOpts)
	if err != nil {
		return "", nil, fmt.Errorf("init httpx runner: %w", err)
	}
	defer r.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			r.Interrupt()
		case <-done:
		}
	}()
	r.RunEnumeration()
	close(done)

	return opts.OutputFile, urls, nil
}
