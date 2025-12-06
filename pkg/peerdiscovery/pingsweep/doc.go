// Package pingsweep provides a library for discovering active hosts on a network
// using ICMP ping sweep.
//
// The package provides two main functions:
//   - DiscoverPeers: Scans a provided list of CIDRs or IPs
//   - Autodiscover: Automatically discovers and scans local network interfaces
//
// Discovery is performed by:
// - Expanding network ranges to individual IPs
// - Sending ICMP echo requests to each IP in parallel using an adaptive waitgroup (10 workers)
// - Collecting responses to identify active hosts
//
// Example usage:
//
//	// Manual scan of specific targets
//	targets := []string{"192.168.1.0/24", "10.0.0.1"}
//	peers, err := pingsweep.DiscoverPeers(ctx, targets)
//
//	// Automatic discovery of local networks
//	peers, err := pingsweep.Autodiscover(ctx)
//
// Privilege Requirements:
// - Raw ICMP sockets require root/admin privileges on most systems
// - Consider using alternative methods if privileges are not available
//
// Limitations:
// - Hosts with ICMP disabled or firewalled will not respond
// - Some networks may rate-limit ICMP traffic
// - Large network scans may take significant time
package pingsweep

