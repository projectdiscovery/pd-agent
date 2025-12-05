package arp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/pd-agent/pkg/peerdiscovery/common"
	mapsutil "github.com/projectdiscovery/utils/maps"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Peer represents a discovered ARP peer
type Peer struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// DiscoverPeers retrieves all ARP peers by first reading the local ARP table,
// then scanning the network in parallel to discover additional peers.
func DiscoverPeers(ctx context.Context) ([]Peer, error) {
	peers := mapsutil.NewSyncLockMap[string, *Peer]()

	// Read local ARP table
	localPeers, err := readLocalARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read local ARP table: %w", err)
	}

	for _, peer := range localPeers {
		key := peer.IP.String()
		peerCopy := peer
		_ = peers.Set(key, &peerCopy)
	}

	// Get /24 network ranges from local interfaces
	networks, err := common.GetLocalNetworks24()
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

		discovered, err := scanNetwork24(ctx, network)
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

// scanNetwork24 scans a /24 network range to discover ARP peers
// Uses UDP connections to trigger OS ARP requests and monitors the ARP table
func scanNetwork24(ctx context.Context, network *net.IPNet) ([]Peer, error) {
	// Verify it's a /24 network
	ones, bits := network.Mask.Size()
	if ones != 24 || bits != 32 {
		return nil, fmt.Errorf("network %s is not a /24 network", network.String())
	}

	// Get initial ARP table state
	initialPeers, err := readLocalARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read initial ARP table: %w", err)
	}

	initialSet := make(map[string]struct{})
	for _, peer := range initialPeers {
		if network.Contains(peer.IP) {
			initialSet[peer.IP.String()] = struct{}{}
		}
	}

	// Expand CIDR to get all IPs in /24 range
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

	// Trigger ARP resolution for each IP using UDP connections
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

		// Skip network and broadcast addresses
		if isNetworkOrBroadcast(ip, network) {
			continue
		}

		awg.Add()
		go func(targetIP net.IP) {
			defer awg.Done()

			// Send UDP packet to trigger ARP resolution
			// The OS will handle the ARP request for us
			conn, err := net.DialTimeout("udp", net.JoinHostPort(targetIP.String(), "12345"), 50*time.Millisecond)
			if err != nil {
				// Connection will fail, but ARP resolution may occur
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

	// Wait for OS ARP requests to complete and ARP table to update
	// Give it time since we're not in a hurry
	time.Sleep(2 * time.Second)

	// Read ARP table again to find new entries
	finalPeers, err := readLocalARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read final ARP table: %w", err)
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

// isNetworkOrBroadcast checks if an IP is the network or broadcast address
func isNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	// Network address
	if ip.Equal(network.IP) {
		return true
	}

	// Broadcast address
	broadcast := make(net.IP, len(network.IP))
	copy(broadcast, network.IP)
	for i := range broadcast {
		broadcast[i] |= ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
