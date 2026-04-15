//go:build windows

package agentdb

import "os/exec"

// defaultGateway parses `route print 0.0.0.0` output to find the default gateway.
func defaultGateway() string {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return ""
	}
	return parseWindowsRoute(string(out))
}

// dnsResolvers parses `ipconfig /all` output to extract DNS server addresses.
func dnsResolvers() []string {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return nil
	}
	return parseWindowsDNS(string(out))
}
