// Package igmp provides a library for discovering alive hosts on a network
// using IGMP (Internet Group Management Protocol) monitoring.
//
// The package provides continuous monitoring of network interfaces for IGMP
// membership reports, which can reveal active hosts participating in multicast
// groups without requiring any open ports on target hosts.
//
// The main function is:
//   - DiscoverPeers: Continuously monitors network interfaces and returns a channel
//     that receives Peer structs as hosts are discovered
//
// Discovery is performed by:
// - Monitoring network interfaces for IGMP membership reports
// - Optionally sending periodic membership queries to trigger immediate reports
// - Extracting source IP addresses from IGMP packets to identify active hosts
// - Using BPF filtering for performance (kernel-level packet filtering)
//
// Example usage:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	config := &igmp.Config{
//		Version:       2,
//		EnableQueries: true,
//		ChannelBuffer: 100,
//	}
//
//	// Start continuous monitoring
//	peerChan, err := igmp.DiscoverPeers(ctx, config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Process discovered peers
//	for peer := range peerChan {
//		log.Printf("Discovered host: %s (Groups: %v)", peer.IP, peer.MulticastGroups)
//	}
//
// Privilege Requirements:
// - Raw sockets and packet capture require root/admin privileges on most systems
// - libpcap/WinPcap must be installed for packet capture
//
// Limitations:
// - Only discovers hosts that are members of multicast groups
// - Works only on the same network segment (Layer 2)
// - May miss hosts not participating in multicast
// - Requires elevated privileges for packet capture
package igmp
