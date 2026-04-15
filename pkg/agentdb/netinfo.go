package agentdb

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// DetectNetInfo enumerates local network interfaces and classifies the
// network environment. It is safe to call from any goroutine; the result
// is a snapshot of the system at the time of the call.
func DetectNetInfo() NetInfo {
	var info NetInfo

	ifaces, err := net.Interfaces()
	if err != nil {
		return info
	}

	for _, iface := range ifaces {
		// Skip down interfaces and loopback.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		ifInfo := InterfaceInfo{Name: iface.Name}
		for _, addr := range addrs {
			cidr := addr.String()
			ifInfo.Addrs = append(ifInfo.Addrs, cidr)

			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if classifyIP(ip) {
				info.PrivateIPs = append(info.PrivateIPs, ip.String())
			} else {
				info.PublicIPs = append(info.PublicIPs, ip.String())
			}
		}
		if len(ifInfo.Addrs) > 0 {
			info.Interfaces = append(info.Interfaces, ifInfo)
		}
	}

	info.Gateway = defaultGateway()
	info.DNSResolvers = dnsResolvers()
	info.NetworkType = deriveNetworkType(info.PublicIPs, info.Gateway)

	return info
}

// parseResolvConf extracts nameserver addresses from resolv.conf content.
func parseResolvConf(content string) []string {
	var resolvers []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				resolvers = append(resolvers, fields[1])
			}
		}
	}
	return resolvers
}

// parseLinuxRoute parses the contents of /proc/net/route and returns the
// default gateway IP as a dotted-quad string. Returns "" if no default
// route is found. The gateway field is 8 hex digits in little-endian byte
// order.
func parseLinuxRoute(content string) string {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Default route has destination 00000000.
		if fields[1] != "00000000" {
			continue
		}
		gw := fields[2]
		if len(gw) != 8 {
			continue
		}
		b, err := hex.DecodeString(gw)
		if err != nil || len(b) != 4 {
			continue
		}
		// /proc/net/route stores the gateway in little-endian byte order.
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	return ""
}

// parseWindowsRoute extracts the default gateway from `route print 0.0.0.0` output.
// The relevant section looks like:
//
//	Network Destination        Netmask          Gateway       Interface  Metric
//	          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
func parseWindowsRoute(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2]
		}
	}
	return ""
}

// parseWindowsDNS extracts DNS server addresses from `ipconfig /all` output.
// Handles both the "DNS Servers" line and continuation lines (indented IPs).
func parseWindowsDNS(output string) []string {
	var resolvers []string
	inDNS := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, "DNS Servers") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				if ip != "" && net.ParseIP(ip) != nil {
					resolvers = append(resolvers, ip)
				}
			}
			inDNS = true
			continue
		}
		if inDNS {
			if trimmed == "" || net.ParseIP(trimmed) == nil {
				inDNS = false
				continue
			}
			resolvers = append(resolvers, trimmed)
		}
	}
	return resolvers
}

// parseDarwinRoute parses the output of `route -n get default` and returns
// the gateway IP. Returns "" if no valid gateway is found (e.g. link-layer
// addresses like "link#4").
func parseDarwinRoute(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		gw := parts[1]
		// Filter out link-layer addresses (e.g. "link#4").
		if strings.Contains(gw, "#") {
			return ""
		}
		return gw
	}
	return ""
}
