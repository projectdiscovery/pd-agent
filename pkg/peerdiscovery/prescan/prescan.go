package prescan

import (
	"fmt"
	"math"
	"net"
	"sort"

	"github.com/projectdiscovery/mapcidr"
)

// SelectIPs returns the top N% of IPs from a CIDR, sorted by priority.
// ratio is 0.0-1.0 (e.g., 0.25 = 25%).
func SelectIPs(cidr string, ratio float64) ([]net.IP, error) {
	// Clamp ratio to valid range
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ips, err := mapcidr.IPAddresses(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR: %w", err)
	}

	if len(ips) == 0 {
		return []net.IP{}, nil
	}

	// Drop network/broadcast addresses
	usableIPs := filterUsableIPs(ips, network)
	if len(usableIPs) == 0 {
		return []net.IP{}, nil
	}

	// Score each IP
	prioritized := make([]PrioritizedIP, 0, len(usableIPs))
	for _, ip := range usableIPs {
		prioritized = append(prioritized, PrioritizedIP{
			IP:       ip,
			Priority: CalculatePriority(ip, network),
		})
	}

	// Sort by priority (high to low), then by IP for stable ordering
	sort.Slice(prioritized, func(i, j int) bool {
		if prioritized[i].Priority != prioritized[j].Priority {
			return prioritized[i].Priority > prioritized[j].Priority
		}
		return compareIP(prioritized[i].IP, prioritized[j].IP) < 0
	})

	targetCount := int(math.Ceil(float64(len(usableIPs)) * ratio))
	// If ratio > 0 but math gives us 0, at least return 1 IP
	if ratio > 0 && targetCount == 0 && len(usableIPs) > 0 {
		targetCount = 1
	}
	if targetCount > len(prioritized) {
		targetCount = len(prioritized)
	}

	result := make([]net.IP, 0, targetCount)
	for i := 0; i < targetCount; i++ {
		result = append(result, prioritized[i].IP)
	}

	return result, nil
}

// SelectIPsWithCount returns exactly N highest-priority IPs from a CIDR.
func SelectIPsWithCount(cidr string, count int) ([]net.IP, error) {
	if count <= 0 {
		return []net.IP{}, nil
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ips, err := mapcidr.IPAddresses(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR: %w", err)
	}

	if len(ips) == 0 {
		return []net.IP{}, nil
	}

	usableIPs := filterUsableIPs(ips, network)
	if len(usableIPs) == 0 {
		return []net.IP{}, nil
	}

	// Score and sort
	prioritized := make([]PrioritizedIP, 0, len(usableIPs))
	for _, ip := range usableIPs {
		prioritized = append(prioritized, PrioritizedIP{
			IP:       ip,
			Priority: CalculatePriority(ip, network),
		})
	}

	sort.Slice(prioritized, func(i, j int) bool {
		if prioritized[i].Priority != prioritized[j].Priority {
			return prioritized[i].Priority > prioritized[j].Priority
		}
		return compareIP(prioritized[i].IP, prioritized[j].IP) < 0
	})

	if count > len(prioritized) {
		count = len(prioritized)
	}

	result := make([]net.IP, 0, count)
	for i := 0; i < count; i++ {
		result = append(result, prioritized[i].IP)
	}

	return result, nil
}

// compareIP compares two IPs. Returns -1 if ip1 < ip2, 0 if equal, 1 if ip1 > ip2.
// IPv4 always comes before IPv6.
func compareIP(ip1, ip2 net.IP) int {
	ip1v4 := ip1.To4()
	ip2v4 := ip2.To4()

	// IPv4 < IPv6
	if ip1v4 != nil && ip2v4 == nil {
		return -1
	}
	if ip1v4 == nil && ip2v4 != nil {
		return 1
	}

	// Both IPv4
	if ip1v4 != nil && ip2v4 != nil {
		for i := 0; i < len(ip1v4); i++ {
			if ip1v4[i] < ip2v4[i] {
				return -1
			}
			if ip1v4[i] > ip2v4[i] {
				return 1
			}
		}
		return 0
	}

	// Both IPv6
	for i := 0; i < len(ip1) && i < len(ip2); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}

	if len(ip1) < len(ip2) {
		return -1
	}
	if len(ip1) > len(ip2) {
		return 1
	}

	return 0
}
