package runtools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// TlsxOptions configures an embedded tlsx scan. Only fields pd-agent actually
// drives are exposed; defaults match the CLI behaviour for everything else.
type TlsxOptions struct {
	// OutputFile receives one JSON Response per line. Required.
	OutputFile string
	// Concurrency is the worker count. Defaults to 25 (matches CLI default).
	Concurrency int
	// Timeout is the per-host TLS handshake timeout. Defaults to 5s.
	Timeout time.Duration
	// Retries is the per-host retry count. Defaults to 3.
	Retries int
	// ScanMode picks the TLS implementation: "ctls" (default), "ztls", "openssl", "auto".
	ScanMode string
}

// tlsxDefaultPort is used when a target has no port suffix — same default as
// the tlsx CLI.
const tlsxDefaultPort = "443"

// RunTlsx scans every target in `targets` and writes one JSON Response per
// reachable host to opts.OutputFile. Targets may be bare hosts or "host:port".
// Returns the output file path. Per-target errors are logged and skipped, not
// surfaced: matching CLI semantics where one bad host doesn't fail the run.
func RunTlsx(ctx context.Context, targets []string, opts TlsxOptions) (string, error) {
	if opts.OutputFile == "" {
		return "", errors.New("RunTlsx: OutputFile is required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 25
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Retries <= 0 {
		opts.Retries = 3
	}
	if opts.ScanMode == "" {
		opts.ScanMode = "ctls"
	}

	service, err := tlsx.New(&clients.Options{
		Timeout:     int(opts.Timeout.Seconds()),
		Retries:     opts.Retries,
		ScanMode:    opts.ScanMode,
		ProbeStatus: true,
		JSON:        true,
	})
	if err != nil {
		return "", fmt.Errorf("init tlsx service: %w", err)
	}

	out, err := os.Create(opts.OutputFile)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()

	// bufio.Writer + mutex is simpler than a channel-funnel goroutine and
	// handles back-pressure naturally: workers block on the lock while the
	// writer drains. Buffer is small because results are small.
	bw := bufio.NewWriter(out)
	defer bw.Flush()

	var (
		mu       sync.Mutex
		writeErr error
	)
	writeLine := func(line []byte) {
		mu.Lock()
		defer mu.Unlock()
		if writeErr != nil {
			return
		}
		if _, err := bw.Write(line); err != nil {
			writeErr = err
			return
		}
		if err := bw.WriteByte('\n'); err != nil {
			writeErr = err
		}
	}

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
dispatch:
	for _, raw := range targets {
		select {
		case <-ctx.Done():
			break dispatch
		default:
		}
		host, port := parseTlsxTarget(raw)
		if host == "" || port == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(h, p string) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := service.Connect(h, "", p)
			if err != nil {
				slog.Debug("tlsx: connect failed", "host", h, "port", p, "err", err)
				return
			}
			line, err := json.Marshal(resp)
			if err != nil {
				slog.Debug("tlsx: marshal failed", "host", h, "port", p, "err", err)
				return
			}
			writeLine(line)
		}(host, port)
	}

	wg.Wait()
	if writeErr != nil {
		return opts.OutputFile, fmt.Errorf("write output: %w", writeErr)
	}
	return opts.OutputFile, nil
}

// parseTlsxTarget splits a "host:port" or bare "host" into (host, port),
// defaulting to port 443. Returns ("", "") if the input is unusable.
func parseTlsxTarget(raw string) (host, port string) {
	if raw == "" {
		return "", ""
	}
	h, p, err := net.SplitHostPort(raw)
	if err == nil {
		return h, p
	}
	// SplitHostPort fails for bare hosts (and IPv6 without brackets, which
	// wouldn't make sense as a tlsx target anyway). Treat as host with
	// default port.
	return raw, tlsxDefaultPort
}
