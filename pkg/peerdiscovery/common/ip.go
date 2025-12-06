package common

import "net"

// IsNetworkOrBroadcast checks if an IP is the network or broadcast address.
// For IPv4, it checks both network and broadcast addresses.
// For IPv6, it checks network address and multicast addresses.
func IsNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	if network == nil {
		return false
	}

	// Check if IP equals network address
	if ip.Equal(network.IP) {
		return true
	}

	// For IPv4, check broadcast address
	if ip4 := ip.To4(); ip4 != nil {
		broadcast := make(net.IP, len(network.IP))
		copy(broadcast, network.IP)
		for i := range broadcast {
			broadcast[i] |= ^network.Mask[i]
		}
		return ip.Equal(broadcast)
	}

	// For IPv6, check multicast addresses
	if ip.IsMulticast() {
		return true
	}

	return false
}

