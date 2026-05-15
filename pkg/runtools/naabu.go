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

// NaabuOptions configures an embedded naabu scan.
type NaabuOptions struct {
	// OutputFile receives one "host:port" line per open port. Required.
	OutputFile string
	// Ports is a comma-separated list (e.g. "80,443,8443"); empty uses naabu's top-1000.
	Ports             string
	SkipHostDiscovery bool
	// ServiceVersion enables nmap-service-probes scanning (no external nmap binary).
	ServiceVersion bool
	// ServiceDiscovery enables port-number-to-service mapping (cheaper than ServiceVersion).
	ServiceDiscovery bool
}

// RunNaabu scans every target and writes one "host:port" line per open port
// to opts.OutputFile.
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

	// RunEnumeration returns an error when no ports are found; treat at call site.
	if err := r.RunEnumeration(ctx); err != nil {
		return opts.OutputFile, fmt.Errorf("naabu enumeration: %w", err)
	}
	return opts.OutputFile, nil
}
