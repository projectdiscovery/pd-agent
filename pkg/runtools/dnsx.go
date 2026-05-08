package runtools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// DnsxOptions configures an embedded dnsx scan. Only fields pd-agent actually
// drives are exposed; defaults match the CLI behaviour for everything else.
type DnsxOptions struct {
	// OutputFile receives one JSON DNSData per line. Required.
	OutputFile string
	// Concurrency is the worker count. Defaults to 25 (matches CLI default).
	Concurrency int
	// Timeout per query is governed by retryabledns; we expose Retries here.
	Retries int
	// Resolvers overrides the default resolver list. Empty means use defaults.
	Resolvers []string
	// QueryAll requests every record type (A/AAAA/CNAME/MX/...). When false
	// (default) only A records are queried, matching dnsx CLI default.
	QueryAll bool
}

// RunDnsx resolves every hostname in `hosts` and writes one JSON DNSData per
// hostname to opts.OutputFile, matching `dnsx -json -o`. Per-host errors are
// logged at DEBUG and skipped — same behaviour as the CLI.
func RunDnsx(ctx context.Context, hosts []string, opts DnsxOptions) (string, error) {
	if opts.OutputFile == "" {
		return "", errors.New("RunDnsx: OutputFile is required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 25
	}
	if opts.Retries <= 0 {
		opts.Retries = 2
	}

	dnsxOpts := dnsx.DefaultOptions
	dnsxOpts.MaxRetries = opts.Retries
	dnsxOpts.QueryAll = opts.QueryAll
	if len(opts.Resolvers) > 0 {
		dnsxOpts.BaseResolvers = opts.Resolvers
	}
	if opts.QueryAll {
		// All record types when QueryAll is set; CLI does the same.
		dnsxOpts.QuestionTypes = []uint16{
			miekgdns.TypeA, miekgdns.TypeAAAA, miekgdns.TypeCNAME,
			miekgdns.TypeMX, miekgdns.TypeNS, miekgdns.TypeTXT,
			miekgdns.TypeSOA, miekgdns.TypeSRV, miekgdns.TypeCAA,
		}
	}

	client, err := dnsx.New(dnsxOpts)
	if err != nil {
		return "", fmt.Errorf("init dnsx client: %w", err)
	}

	out, err := os.Create(opts.OutputFile)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()

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
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			break dispatch
		default:
		}
		if host == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			data, err := client.QueryMultiple(h)
			if err != nil || data == nil {
				slog.Debug("dnsx: query failed", "host", h, "err", err)
				return
			}
			data.Timestamp = time.Now()
			line, err := json.Marshal(data)
			if err != nil {
				slog.Debug("dnsx: marshal failed", "host", h, "err", err)
				return
			}
			writeLine(line)
		}(host)
	}

	wg.Wait()
	if writeErr != nil {
		return opts.OutputFile, fmt.Errorf("write output: %w", writeErr)
	}
	return opts.OutputFile, nil
}
