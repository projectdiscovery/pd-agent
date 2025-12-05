package prescan

import (
	"net"

	"github.com/projectdiscovery/pd-agent/pkg/peerdiscovery/common"
)

// PrioritizedIP holds an IP and its priority score (0-100)
type PrioritizedIP struct {
	IP       net.IP
	Priority int
}

// CalculatePriority returns priority score (0-100) for an IP in a network.
// Higher scores mean more likely to be online. IPv6 uses default priority.
func CalculatePriority(ip net.IP, network *net.IPNet) int {
	if network == nil {
		return PriorityTier6
	}

	if ip.To4() != nil {
		return adaptPriorityForSubnet(ip, network)
	}

	// IPv6 support TODO
	return PriorityTier6
}

// filterUsableIPs drops network/broadcast addresses from the list
func filterUsableIPs(ips []string, network *net.IPNet) []net.IP {
	var usableIPs []net.IP

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		if common.IsNetworkOrBroadcast(ip, network) {
			continue
		}

		usableIPs = append(usableIPs, ip)
	}

	return usableIPs
}
