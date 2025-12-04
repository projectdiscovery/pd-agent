package ndp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/mapcidr"
	mapsutil "github.com/projectdiscovery/utils/maps"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Peer represents a discovered NDP peer
type Peer struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// DiscoverPeers retrieves all NDP peers by first reading the local NDP table,
// then scanning the network in parallel to discover additional peers.
func DiscoverPeers(ctx context.Context) ([]Peer, error) {
	peers := mapsutil.NewSyncLockMap[string, *Peer]()

	// Read local NDP table
	localPeers, err := readLocalNDPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read local NDP table: %w", err)
	}

	for _, peer := range localPeers {
		key := peer.IP.String()
		peerCopy := peer
		_ = peers.Set(key, &peerCopy)
	}

	// Get /64 network ranges from local interfaces
	networks, err := getLocalNetworks64()
	if err != nil {
		return nil, fmt.Errorf("failed to get local networks: %w", err)
	}

	// Scan networks sequentially (no hurry)
	for _, network := range networks {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		discovered, err := scanNetwork64(ctx, network)
		if err != nil {
			continue
		}

		for _, peer := range discovered {
			key := peer.IP.String()
			if _, exists := peers.Get(key); !exists {
				peerCopy := peer
				_ = peers.Set(key, &peerCopy)
			}
		}
	}

done:
	// Convert map to slice
	var result []Peer
	_ = peers.Iterate(func(key string, peer *Peer) error {
		if peer != nil {
			result = append(result, *peer)
		}
		return nil
	})

	return result, nil
}

// getLocalNetworks64 returns all local network interfaces as /64 IPNet ranges
func getLocalNetworks64() ([]*net.IPNet, error) {
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

// scanNetwork64 scans a /64 network range to discover NDP peers
// Uses UDP6 connections to trigger OS NDP requests and monitors the NDP table
func scanNetwork64(ctx context.Context, network *net.IPNet) ([]Peer, error) {
	// Verify it's a /64 network
	ones, bits := network.Mask.Size()
	if ones != 64 || bits != 128 {
		return nil, fmt.Errorf("network %s is not a /64 network", network.String())
	}

	// Get initial NDP table state
	initialPeers, err := readLocalNDPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read initial NDP table: %w", err)
	}

	initialSet := make(map[string]struct{})
	for _, peer := range initialPeers {
		if network.Contains(peer.IP) {
			initialSet[peer.IP.String()] = struct{}{}
		}
	}

	// Expand CIDR to get all IPs in /64 range
	cidrStr := network.String()
	ips, err := mapcidr.IPAddresses(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR %s: %w", cidrStr, err)
	}

	if len(ips) == 0 {
		return []Peer{}, nil
	}

	// Use adaptive waitgroup with low parallelism (no hurry)
	awg, err := syncutil.New(syncutil.WithSize(5))
	if err != nil {
		return nil, fmt.Errorf("failed to create adaptive waitgroup: %w", err)
	}

	// Trigger NDP resolution for each IP using UDP6 connections
	for _, ipStr := range ips {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Skip network and multicast addresses
		if isNetworkOrMulticast(ip, network) {
			continue
		}

		awg.Add()
		go func(targetIP net.IP) {
			defer awg.Done()

			// Send UDP6 packet to trigger NDP resolution
			// The OS will handle the NDP Neighbor Solicitation for us
			conn, err := net.DialTimeout("udp6", net.JoinHostPort(targetIP.String(), "12345"), 50*time.Millisecond)
			if err != nil {
				// Connection will fail, but NDP resolution may occur
				return
			}
			if conn != nil {
				_ = conn.Close()
			}
		}(ip)

		// Small delay between requests to avoid overwhelming
		time.Sleep(10 * time.Millisecond)
	}

done:
	awg.Wait()

	// Wait for OS NDP requests to complete and NDP table to update
	// Give it time since we're not in a hurry
	time.Sleep(2 * time.Second)

	// Read NDP table again to find new entries
	finalPeers, err := readLocalNDPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read final NDP table: %w", err)
	}

	// Find newly discovered peers
	var discovered []Peer
	for _, peer := range finalPeers {
		if !network.Contains(peer.IP) {
			continue
		}

		// Check if this is a new peer
		if _, exists := initialSet[peer.IP.String()]; !exists {
			discovered = append(discovered, peer)
		}
	}

	return discovered, nil
}

// isNetworkOrMulticast checks if an IPv6 address is the network or multicast address
// IPv6 doesn't have broadcast, uses multicast instead
func isNetworkOrMulticast(ip net.IP, network *net.IPNet) bool {
	// Network address
	if ip.Equal(network.IP) {
		return true
	}

	// Check if it's a multicast address
	if ip.IsMulticast() {
		return true
	}

	// Skip all-nodes multicast (ff02::1)
	if ip.Equal(net.ParseIP("ff02::1")) {
		return true
	}

	return false
}
