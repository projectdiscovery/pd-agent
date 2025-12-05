package igmp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Peer represents a discovered IGMP peer
type Peer struct {
	IP              net.IP
	MAC             net.HardwareAddr // Optional, may be nil
	MulticastGroups []string          // List of multicast groups the host belongs to
	LastSeen        time.Time         // When the host was last detected
	ResponseTime    time.Duration     // Time to receive IGMP response
	IGMPVersion     int               // IGMP version detected (1, 2, or 3)
}

// Config holds configuration for IGMP discovery
type Config struct {
	// IGMP version to use (1, 2, or 3)
	Version int // Default: 2

	// Multicast groups to query
	MulticastGroups []net.IP // Default: common multicast groups

	// Network interface
	Interface *net.Interface // Specific interface to use (nil = all)

	// Discovery settings
	QueryInterval time.Duration // Interval between membership queries (default: 125s for IGMPv2)
	EnableQueries bool         // Enable periodic membership queries (default: true)

	// Channel buffer size for discovered peers
	ChannelBuffer int // Default: 100

	// Enable BPF filtering
	EnableBPF bool // Default: true
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Version:        2,
		MulticastGroups: CommonMulticastGroups,
		Interface:      nil, // All interfaces
		QueryInterval:  125 * time.Second,
		EnableQueries:  true,
		ChannelBuffer:  100,
		EnableBPF:      true,
	}
}

// DiscoverPeers continuously monitors network interfaces for IGMP messages
// and sends discovered peers to the returned channel.
// The function runs until the context is cancelled.
// Returns a channel that receives Peer structs as hosts are discovered.
func DiscoverPeers(ctx context.Context, config *Config) (<-chan Peer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create buffered channel for discovered peers
	peerChan := make(chan Peer, config.ChannelBuffer)

	// Get network interfaces to monitor
	var interfaces []*net.Interface

	if config.Interface != nil {
		// Monitor specific interface
		interfaces = []*net.Interface{config.Interface}
	} else {
		// Get all local network interfaces
		allInterfaces, err := net.Interfaces()
		if err != nil {
			close(peerChan)
			return nil, fmt.Errorf("failed to get network interfaces: %w", err)
		}

		// Filter to only active, non-loopback interfaces
		for i := range allInterfaces {
			iface := &allInterfaces[i]
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			interfaces = append(interfaces, iface)
		}
	}

	if len(interfaces) == 0 {
		close(peerChan)
		return nil, fmt.Errorf("no suitable network interfaces found")
	}

	// Use sync.WaitGroup to track monitor goroutines
	// Channel will be closed when all monitors finish or context is cancelled
	var wg sync.WaitGroup

	// Start monitoring goroutines for each interface
	for _, iface := range interfaces {
		select {
		case <-ctx.Done():
			close(peerChan)
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		// Start monitoring goroutine for this interface
		go func(interfaceToMonitor *net.Interface) {
			defer wg.Done()
			if err := monitorInterface(ctx, interfaceToMonitor, config, peerChan); err != nil {
				// Log error but don't fail entire discovery
				// Errors are expected if interface becomes unavailable
				_ = err
			}
		}(iface)
	}

	// Start periodic query goroutine if enabled
	if config.EnableQueries {
		go sendPeriodicQueries(ctx, interfaces, config)
	}

	// Start goroutine to close channel when all monitors finish or context is done
	go func() {
		// Wait for context cancellation or all monitors to finish
		done := make(chan struct{})
		go func() {
			<-ctx.Done()
			close(done)
		}()
		go func() {
			wg.Wait()
			close(done)
		}()

		<-done
		// Give a small grace period for final packets to be sent
		time.Sleep(200 * time.Millisecond)
		close(peerChan)
	}()

	return peerChan, nil
}

// monitorInterface monitors a specific network interface for IGMP messages
// and sends discovered peers to the provided channel.
// Runs until context is cancelled.
func monitorInterface(ctx context.Context, iface *net.Interface, config *Config, peerChan chan<- Peer) error {
	// Create packet capture handle
	handle, err := createCaptureHandle(iface, config)
	if err != nil {
		return fmt.Errorf("failed to create capture handle for %s: %w", iface.Name, err)
	}
	defer handle.Close()

	// Set BPF filter if enabled
	if config.EnableBPF {
		filter := "ip proto 2 and (ip[20] == 0x12 or ip[20] == 0x16 or ip[20] == 0x22)"
		if err := handle.SetBPFFilter(filter); err != nil {
			// Log warning but continue without filter
			// BPF filter is optional for functionality
			_ = err
		}
	}

	// Create packet source
	packetSource := newPacketSource(handle)

	// Process packets from packet source channel
	packetChan := packetSource.source.Packets()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet, ok := <-packetChan:
			if !ok {
				// Channel closed (handle closed)
				return nil
			}
			if packet == nil {
				continue
			}

			// Parse and process IGMP packet
			peer, err := parseIGMPPacket(packet, iface)
			if err != nil {
				// Skip invalid packets (not IGMP, wrong type, etc.)
				continue
			}

			if peer == nil {
				continue
			}

			// Send peer to channel (non-blocking with timeout to avoid blocking)
			select {
			case peerChan <- *peer:
				// Successfully sent
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
				// Channel full, skip this peer to avoid blocking monitor
				// This prevents one slow consumer from blocking all monitors
				// The timeout ensures we don't block indefinitely
				continue
			}
		}
	}
}

// sendPeriodicQueries sends periodic IGMP membership queries to trigger reports
func sendPeriodicQueries(ctx context.Context, interfaces []*net.Interface, config *Config) {
	ticker := time.NewTicker(config.QueryInterval)
	defer ticker.Stop()

	// Send initial query immediately
	sendQueriesToInterfaces(ctx, interfaces, config)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendQueriesToInterfaces(ctx, interfaces, config)
		}
	}
}

// sendQueriesToInterfaces sends membership queries on all interfaces
func sendQueriesToInterfaces(ctx context.Context, interfaces []*net.Interface, config *Config) {
	for _, iface := range interfaces {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Send query to common multicast groups
		for _, group := range config.MulticastGroups {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Send query (non-blocking, errors are ignored)
			_ = sendMembershipQuery(iface, group, config.Version)
		}
	}
}

