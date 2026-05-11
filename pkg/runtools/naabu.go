package runtools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// NaabuOptions configures an embedded naabu scan. Mirrors the CLI flags
// pd-agent actually uses today.
type NaabuOptions struct {
	// OutputFile receives one "host:port" line per open port. Required.
	OutputFile string
	// Ports is a comma-separated list (e.g. "80,443,8443"). Empty means
	// naabu's default top-1000.
	Ports string
	// SkipHostDiscovery is the equivalent of nmap -Pn: don't try to ping the
	// host first, just probe the ports.
	SkipHostDiscovery bool
	// ServiceVersion enables naabu's native service-version detection
	// (equivalent of the CLI's -sV). Uses nmap-service-probes natively,
	// no external nmap binary needed.
	ServiceVersion bool
	// ServiceDiscovery enables naabu's port-number-to-service mapping
	// (CLI -sD). Cheaper than ServiceVersion.
	ServiceDiscovery bool
}

// RunNaabu scans every target in `hosts` and writes one "host:port" line per
// open port to opts.OutputFile. Returns the path on success.
func RunNaabu(ctx context.Context, hosts []string, opts NaabuOptions) (string, error) {
	if opts.OutputFile == "" {
		return "", errors.New("RunNaabu: OutputFile is required")
	}

	out, err := os.Create(opts.OutputFile)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()

	bw := bufio.NewWriter(out)
	defer bw.Flush()

	var mu sync.Mutex
	naabuOpts := &runner.Options{
		Host:              goflags.StringSlice(hosts),
		Ports:             opts.Ports,
		SkipHostDiscovery: opts.SkipHostDiscovery,
		ServiceVersion:    opts.ServiceVersion,
		ServiceDiscovery:  opts.ServiceDiscovery,
		Silent:            true,
		OnResult: func(hr *result.HostResult) {
			if hr == nil || hr.Host == "" || len(hr.Ports) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range hr.Ports {
				line := net.JoinHostPort(hr.Host, strconv.Itoa(p.Port))
				if _, err := bw.WriteString(line); err != nil {
					return
				}
				if err := bw.WriteByte('\n'); err != nil {
					return
				}
			}
		},
	}

	r, err := runner.NewRunner(naabuOpts)
	if err != nil {
		return "", fmt.Errorf("init naabu runner: %w", err)
	}
	defer r.Close()

	// naabu's RunEnumeration returns an error when no ports are found; that's
	// not a failure for our pipeline, so log-and-continue at the call site.
	if err := r.RunEnumeration(ctx); err != nil {
		return opts.OutputFile, fmt.Errorf("naabu enumeration: %w", err)
	}
	return opts.OutputFile, nil
}
