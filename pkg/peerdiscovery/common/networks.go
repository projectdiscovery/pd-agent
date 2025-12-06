package common

import (
	"net"
)

// GetLocalNetworks24 returns all local network interfaces as /24 IPNet ranges (IPv4 only)
func GetLocalNetworks24() ([]*net.IPNet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var networks []*net.IPNet
	seen := make(map[string]struct{})

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Only process IPv4 addresses
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}

			// Only process private networks
			if !ip.IsPrivate() {
				continue
			}

			// Convert to /24 network
			mask24 := net.CIDRMask(24, 32)
			network24 := &net.IPNet{
				IP:   ip.Mask(mask24),
				Mask: mask24,
			}

			// Avoid duplicates
			key := network24.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			networks = append(networks, network24)
		}
	}

	return networks, nil
}

// GetLocalNetworks64 returns all local network interfaces as /64 IPNet ranges (IPv6 only)
func GetLocalNetworks64() ([]*net.IPNet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var networks []*net.IPNet
	seen := make(map[string]struct{})

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP

			// Only process IPv6 addresses
			if ip.To4() != nil {
				continue
			}

			// Must be 16 bytes for IPv6
			if len(ip) != net.IPv6len {
				continue
			}

			// Skip loopback
			if ip.IsLoopback() {
				continue
			}

			// Skip multicast
			if ip.IsMulticast() {
				continue
			}

			// Only process link-local and ULA (private) addresses
			// Link-local: fe80::/10
			// ULA: fc00::/7 (actually fd00::/8 is used for ULA)
			isLinkLocal := ip.IsLinkLocalUnicast()
			// ULA addresses start with fd (fd00::/8)
			isULA := len(ip) == net.IPv6len && ip[0] == 0xfd

			if !isLinkLocal && !isULA {
				continue
			}

			// Convert to /64 network (IPv6 standard)
			mask64 := net.CIDRMask(64, 128)
			network64 := &net.IPNet{
				IP:   ip.Mask(mask64),
				Mask: mask64,
			}

			// Avoid duplicates
			key := network64.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			networks = append(networks, network64)
		}
	}

	return networks, nil
}

// GetLocalNetworks returns all local network interfaces as IPNet ranges
// Supports both IPv4 (/24) and IPv6 (/64) networks
func GetLocalNetworks() ([]*net.IPNet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var networks []*net.IPNet
	seen := make(map[string]struct{})

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP

			// Handle IPv4 addresses
			if ip4 := ip.To4(); ip4 != nil {
				// Only process private networks
				if !ip4.IsPrivate() {
					continue
				}

				// Convert to /24 network
				mask24 := net.CIDRMask(24, 32)
				network24 := &net.IPNet{
					IP:   ip4.Mask(mask24),
					Mask: mask24,
				}

				// Avoid duplicates
				key := network24.String()
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}

				networks = append(networks, network24)
				continue
			}

			// Handle IPv6 addresses
			if len(ip) == net.IPv6len {
				// Skip loopback
				if ip.IsLoopback() {
					continue
				}

				// Skip multicast
				if ip.IsMulticast() {
					continue
				}

				// Only process link-local and ULA (private) addresses
				isLinkLocal := ip.IsLinkLocalUnicast()
				// ULA addresses start with fd (fd00::/8)
				isULA := ip[0] == 0xfd

				if !isLinkLocal && !isULA {
					continue
				}

				// Convert to /64 network (IPv6 standard)
				mask64 := net.CIDRMask(64, 128)
				network64 := &net.IPNet{
					IP:   ip.Mask(mask64),
					Mask: mask64,
				}

				// Avoid duplicates
				key := network64.String()
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}

				networks = append(networks, network64)
			}
		}
	}

	return networks, nil
}
