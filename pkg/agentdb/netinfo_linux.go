//go:build linux

package agentdb

import "os"

// defaultGateway reads /proc/net/route and returns the default gateway IP.
func defaultGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return parseLinuxRoute(string(data))
}

// dnsResolvers reads /etc/resolv.conf and returns the configured nameservers.
func dnsResolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(string(data))
}
