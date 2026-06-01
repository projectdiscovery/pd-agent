package runtools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// NaabuOptions configures an embedded naabu scan.
type NaabuOptions struct {
	// OutputFile receives one "host:port" line per open port. Required.
	OutputFile string
	// Ports is the control-plane port spec: "top-<N>" (e.g. "top-100"), "full",
	// or a literal list/range ("80,443", "1-1000"). Empty uses naabu's default.
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
	setNaabuPorts(naabuOpts, opts.Ports)

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

// setNaabuPorts routes the control-plane port spec to the right naabu field.
// "top-<N>" and "full" select naabu's top-ports list (-top-ports); a literal
// list/range goes to -p. Passing "top-100" to Ports makes naabu read it as a
// range and fail with "invalid port number: 'top'".
func setNaabuPorts(o *runner.Options, spec string) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "":
		// leave naabu's default
	case strings.EqualFold(spec, "full"):
		o.TopPorts = "full"
	case strings.HasPrefix(spec, "top-"):
		o.TopPorts = strings.TrimPrefix(spec, "top-")
	default:
		o.Ports = spec
	}
}
