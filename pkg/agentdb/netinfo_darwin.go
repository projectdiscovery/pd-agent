//go:build darwin

package agentdb

import (
	"os"
	"os/exec"
	"strings"
)

// defaultGateway returns the default gateway IP by running `route -n get default`.
func defaultGateway() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	return parseDarwinRoute(string(out))
}

// dnsResolvers reads /etc/resolv.conf and returns the configured nameservers.
func dnsResolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		// macOS may not have resolv.conf; try scutil as a fallback.
		return dnsResolversFromScutil()
	}
	resolvers := parseResolvConf(string(data))
	if len(resolvers) == 0 {
		return dnsResolversFromScutil()
	}
	return resolvers
}

// dnsResolversFromScutil uses `scutil --dns` to extract nameservers on macOS
// when resolv.conf is absent or empty.
func dnsResolversFromScutil() []string {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	var resolvers []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			// Format: "nameserver[0] : 8.8.8.8"
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				if ip != "" && !seen[ip] {
					seen[ip] = true
					resolvers = append(resolvers, ip)
				}
			}
		}
	}
	return resolvers
}
