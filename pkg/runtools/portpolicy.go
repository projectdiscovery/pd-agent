package runtools

import (
	"net"
	"strconv"
	"strings"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// Raw print-spooler ports are excluded from enumeration because probe bytes
// can be treated as print data.
const (
	deniedProbePortMin = 9100
	deniedProbePortMax = 9107
)

// httpx, tlsx and nuclei each build their dialer from a copy of
// fastdialer.DefaultOptions and expose no way to inject one, so the deny list
// is installed on the package default before any tool runs. fastdialer checks
// it on every dial, which is what catches redirect targets httpx never
// re-validates. Process-wide by design: pd-agent has no allowed use of these
// ports.
func init() {
	fastdialer.DefaultOptions.DenyPortList = append(fastdialer.DefaultOptions.DenyPortList, DeniedProbePorts()...)
}

// IsDeniedProbePort reports whether port must not receive probe bytes.
func IsDeniedProbePort(port int) bool {
	return port >= deniedProbePortMin && port <= deniedProbePortMax
}

// DeniedProbePorts returns the deny set as ints (fastdialer DenyPortList).
func DeniedProbePorts() []int {
	out := make([]int, 0, deniedProbePortMax-deniedProbePortMin+1)
	for p := deniedProbePortMin; p <= deniedProbePortMax; p++ {
		out = append(out, p)
	}
	return out
}

// DeniedProbePortStrings returns the deny set as strings (httpx Exclude).
func DeniedProbePortStrings() []string {
	out := make([]string, 0, deniedProbePortMax-deniedProbePortMin+1)
	for p := deniedProbePortMin; p <= deniedProbePortMax; p++ {
		out = append(out, strconv.Itoa(p))
	}
	return out
}

// FilterDeniedProbePorts drops "host:port" targets whose port is denied.
// Bare hosts and unparseable targets pass through unchanged.
func FilterDeniedProbePorts(targets []string) (kept, dropped []string) {
	kept = make([]string, 0, len(targets))
	for _, t := range targets {
		_, portStr, err := net.SplitHostPort(t)
		if err == nil {
			if port, perr := strconv.Atoi(portStr); perr == nil && IsDeniedProbePort(port) {
				dropped = append(dropped, t)
				continue
			}
		}
		kept = append(kept, t)
	}
	return kept, dropped
}

// StripDeniedProbePorts trims targets, rewrites "host:<denied>" inputs to the
// bare host so its other ports are still discovered, and dedupes the result. Meant
// for scanner inputs (naabu); probe inputs use FilterDeniedProbePorts, since
// there the port is the whole target.
func StripDeniedProbePorts(targets []string) []string {
	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		// Match naabu's normalization before checking its per-target port.
		t = strings.TrimSpace(t)
		host, portStr, err := net.SplitHostPort(t)
		if err == nil {
			if port, perr := strconv.Atoi(portStr); perr == nil && IsDeniedProbePort(port) {
				t = host
			}
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

// ChromeHostResolverRules returns a --host-resolver-rules value that makes
// Chrome fail resolution for any host on a denied port, so headless
// screenshots cannot reach one through a redirect or a subresource. Applies
// to IP literals as well as hostnames.
func ChromeHostResolverRules() string {
	ports := DeniedProbePorts()
	rules := make([]string, 0, len(ports))
	for _, p := range ports {
		rules = append(rules, "MAP *:"+strconv.Itoa(p)+" ~NOTFOUND")
	}
	return strings.Join(rules, ",")
}
