package pingsweep

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/pd-agent/pkg/peerdiscovery/common"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"golang.org/x/net/icmp"
)

// Peer represents a discovered ping peer
type Peer struct {
	IP  net.IP
	MAC net.HardwareAddr // Optional, may be nil
	RTT time.Duration    // Round-trip time for the ping
}

// DiscoverPeers scans the provided CIDRs or IPs and returns discovered active peers
// targets can be CIDR notation (e.g., "192.168.1.0/24") or individual IPs (e.g., "192.168.1.1")
func DiscoverPeers(ctx context.Context, targets []string) ([]Peer, error) {
	peers := mapsutil.NewSyncLockMap[string, *Peer]()

	// Parse targets into networks and individual IPs
	networks, individualIPs, err := parseTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to parse targets: %w", err)
	}

	// Scan networks
	for _, network := range networks {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		discovered, err := scanNetwork(ctx, network)
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

	// Scan individual IPs
	if len(individualIPs) > 0 {
		discovered, err := scanIPs(ctx, individualIPs)
		if err == nil {
			for _, peer := range discovered {
				key := peer.IP.String()
				if _, exists := peers.Get(key); !exists {
					peerCopy := peer
					_ = peers.Set(key, &peerCopy)
				}
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

// Autodiscover retrieves all active peers by automatically discovering and scanning local networks using ICMP pings
func Autodiscover(ctx context.Context) ([]Peer, error) {
	// Get local network ranges from local interfaces
	networks, err := common.GetLocalNetworks()
	if err != nil {
		return nil, fmt.Errorf("failed to get local networks: %w", err)
	}

	// Convert networks to string targets
	targets := make([]string, 0, len(networks))
	for _, network := range networks {
		targets = append(targets, network.String())
	}

	return DiscoverPeers(ctx, targets)
}

// parseTargets parses a list of target strings into networks and individual IPs
func parseTargets(targets []string) ([]*net.IPNet, []net.IP, error) {
	var networks []*net.IPNet
	var individualIPs []net.IP
	seenNetworks := make(map[string]struct{})
	seenIPs := make(map[string]struct{})

	for _, target := range targets {
		// Try to parse as CIDR first
		_, ipNet, err := net.ParseCIDR(target)
		if err == nil {
			// It's a CIDR
			key := ipNet.String()
			if _, exists := seenNetworks[key]; !exists {
				seenNetworks[key] = struct{}{}
				networks = append(networks, ipNet)
			}
			continue
		}

		// Try to parse as individual IP
		ip := net.ParseIP(target)
		if ip != nil {
			key := ip.String()
			if _, exists := seenIPs[key]; !exists {
				seenIPs[key] = struct{}{}
				individualIPs = append(individualIPs, ip)
			}
			continue
		}

		// Neither CIDR nor IP
		return nil, nil, fmt.Errorf("invalid target format: %s (must be CIDR or IP)", target)
	}

	return networks, individualIPs, nil
}

// scanNetwork scans a network range to discover active peers using ICMP pings
func scanNetwork(ctx context.Context, network *net.IPNet) ([]Peer, error) {
	// Expand CIDR to get all IPs in range
	cidrStr := network.String()
	ips, err := mapcidr.IPAddresses(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR %s: %w", cidrStr, err)
	}

	if len(ips) == 0 {
		return []Peer{}, nil
	}

	// Filter IPs and determine if IPv4 or IPv6
	var targetIPs []net.IP
	isIPv6 := false
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Skip network and broadcast/multicast addresses
		if isNetworkOrBroadcast(ip, network) {
			continue
		}

		if ip.To4() == nil {
			isIPv6 = true
		}
		targetIPs = append(targetIPs, ip)
	}

	if len(targetIPs) == 0 {
		return []Peer{}, nil
	}

	// Use shared connection approach for better reply matching
	return scanIPsWithSharedConnection(ctx, targetIPs, isIPv6)
}

// scanIPs scans a list of individual IPs to discover active peers using ICMP pings
func scanIPs(ctx context.Context, ips []net.IP) ([]Peer, error) {
	if len(ips) == 0 {
		return []Peer{}, nil
	}

	// Determine if IPv4 or IPv6
	isIPv6 := false
	for _, ip := range ips {
		if ip.To4() == nil {
			isIPv6 = true
			break
		}
	}

	// Use shared connection approach for better reply matching
	return scanIPsWithSharedConnection(ctx, ips, isIPv6)
}

// scanIPsWithSharedConnection uses a shared ICMP connection to send pings and match replies
func scanIPsWithSharedConnection(ctx context.Context, ips []net.IP, isIPv6 bool) ([]Peer, error) {
	const maxRetries = 4
	// Match ping command timeout: default is typically 1-2 seconds, use 2 seconds to account for network latency
	const pingTimeout = 2 * time.Second

	// Create shared ICMP connection
	conn, err := createSharedICMPConnection(isIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create shared ICMP connection: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Map to track pending pings: sequence number -> pending ping info
	pendingPings := mapsutil.NewSyncLockMap[int, *pendingPing]()

	// Map to store successful peers
	peers := mapsutil.NewSyncLockMap[string, *Peer]()

	// Channel for receiver to signal completion
	receiverDone := make(chan struct{})

	// Start receiver goroutine to match replies
	go func() {
		defer close(receiverDone)
		receiveReplies(ctx, conn, pendingPings, peers, isIPv6, pingTimeout)
	}()

	// Generate unique sequence numbers starting from 1
	seqCounter := 0
	getNextSeq := func() int {
		seqCounter++
		return seqCounter
	}

	// Iterate over input for retries times (initial attempt + maxRetries)
	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		// Send pings for all IPs in this attempt
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				goto done
			default:
			}

			// Skip if we already have a successful peer for this IP
			if _, exists := peers.Get(ip.String()); exists {
				continue
			}

			seq := getNextSeq()
			start := time.Now()

			// Track pending ping
			pending := &pendingPing{
				IP:      ip,
				Start:   start,
				Seq:     seq,
				Retries: attempt,
			}
			_ = pendingPings.Set(seq, pending)

			// Send ping
			if err := sendPing(conn, ip, seq, isIPv6); err != nil {
				pendingPings.Delete(seq)
				continue
			}
		}

		// Wait for replies before next attempt (except on last attempt)
		// Match ping command behavior: wait for timeout before retrying
		if attempt < maxRetries {
			time.Sleep(pingTimeout)
		}
	}

done:
	// Wait for final replies - match ping command final wait time
	// Give extra time for any delayed replies
	finalTimeout := pingTimeout
	select {
	case <-receiverDone:
	case <-time.After(finalTimeout):
		// Receiver should finish on its own, but we have a timeout
	case <-ctx.Done():
	}

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

// pendingPing tracks a sent ping waiting for reply
type pendingPing struct {
	IP      net.IP
	Start   time.Time
	Seq     int
	Retries int
}

// createSharedICMPConnection creates a shared ICMP connection
func createSharedICMPConnection(isIPv6 bool) (net.PacketConn, error) {
	if isIPv6 {
		return icmp.ListenPacket("ip6:ipv6-icmp", "::")
	}
	return icmp.ListenPacket("ip4:icmp", "0.0.0.0")
}

// isNetworkOrBroadcast checks if an IP is the network or broadcast/multicast address
func isNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	// Network address
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

	// Skip all-nodes multicast (ff02::1)
	if ip.Equal(net.ParseIP("ff02::1")) {
		return true
	}

	return false
}
