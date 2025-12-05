package prescan

import (
	"net"

	"github.com/projectdiscovery/pd-agent/pkg/peerdiscovery/common"
)

// DistributionPattern maps an IP range to a priority tier
type DistributionPattern struct {
	RangeStart  int
	RangeEnd    int
	Priority    int
	Description string
}

// Priority tiers based on real-world network patterns
const (
	PriorityTier1 = 100 // .1, .254 (routers/gateways)
	PriorityTier2 = 90  // .2-.5, .250-.253 (reserved)
	PriorityTier3 = 80  // .6-.10 (early DHCP)
	PriorityTier4 = 70  // .50, .100, .150 (DHCP peaks)
	PriorityTier5 = 50  // .51-.99, .101-.149, .151-.200 (DHCP pool)
	PriorityTier6 = 20  // .11-.49, .201-.249 (long-tail)
	PriorityTier7 = 0   // .0, .255 (excluded)
)

// getDistributionPatterns returns the priority patterns for /24 networks
func getDistributionPatterns() []DistributionPattern {
	return []DistributionPattern{
		// Routers/gateways - check these first
		{RangeStart: 1, RangeEnd: 1, Priority: PriorityTier1, Description: "Router/switch management"},
		{RangeStart: 254, RangeEnd: 254, Priority: PriorityTier1, Description: "Gateway/router"},

		// Reserved infrastructure
		{RangeStart: 2, RangeEnd: 5, Priority: PriorityTier2, Description: "Infrastructure reserved"},
		{RangeStart: 250, RangeEnd: 253, Priority: PriorityTier2, Description: "High-end reserved"},

		// Early DHCP - devices that connect first
		{RangeStart: 6, RangeEnd: 10, Priority: PriorityTier3, Description: "Early DHCP allocation"},

		// DHCP allocation peaks
		{RangeStart: 50, RangeEnd: 50, Priority: PriorityTier4, Description: "DHCP peak 1"},
		{RangeStart: 100, RangeEnd: 100, Priority: PriorityTier4, Description: "DHCP peak 2"},
		{RangeStart: 150, RangeEnd: 150, Priority: PriorityTier4, Description: "DHCP peak 3"},

		// Main DHCP pool
		{RangeStart: 51, RangeEnd: 99, Priority: PriorityTier5, Description: "DHCP range 1"},
		{RangeStart: 101, RangeEnd: 149, Priority: PriorityTier5, Description: "DHCP range 2"},
		{RangeStart: 151, RangeEnd: 200, Priority: PriorityTier5, Description: "DHCP range 3"},

		// Long-tail - lower probability
		{RangeStart: 11, RangeEnd: 49, Priority: PriorityTier6, Description: "Long-tail 1"},
		{RangeStart: 201, RangeEnd: 249, Priority: PriorityTier6, Description: "Long-tail 2"},

		// Excluded addresses
		{RangeStart: 0, RangeEnd: 0, Priority: PriorityTier7, Description: "Network address"},
		{RangeStart: 255, RangeEnd: 255, Priority: PriorityTier7, Description: "Broadcast address"},
	}
}

// calculateIPv4Priority scores an IPv4 address based on last octet patterns.
func calculateIPv4Priority(ip net.IP, network *net.IPNet) int {
	ip4 := ip.To4()
	if ip4 == nil {
		return PriorityTier6
	}

	lastOctet := int(ip4[3])

	// Skip network/broadcast
	if common.IsNetworkOrBroadcast(ip, network) {
		return PriorityTier7
	}

	// Match against known patterns
	patterns := getDistributionPatterns()
	for _, pattern := range patterns {
		if lastOctet >= pattern.RangeStart && lastOctet <= pattern.RangeEnd {
			return pattern.Priority
		}
	}

	return PriorityTier6
}

// adaptPriorityForSubnet handles non-/24 subnets using /24 logic for now.
func adaptPriorityForSubnet(ip net.IP, network *net.IPNet) int {
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return PriorityTier6
	}

	// /24 gets the full treatment
	if ones == 24 {
		return calculateIPv4Priority(ip, network)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return PriorityTier6
	}

	if common.IsNetworkOrBroadcast(ip, network) {
		return PriorityTier7
	}

	// For other sizes, just use /24 logic for now
	return calculateIPv4Priority(ip, network)
}
