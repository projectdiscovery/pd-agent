// Package arp provides a library for discovering ARP peers on a network.
// discovery is performed in a slow fashion
// - The agent monitors the ARP table for changes
// - The agent sends UDP packets to the target IP to trigger ARP resolution
// - The agent waits for the ARP resolution to complete before continuing with the next target IP
// - The agent reads the ARP table again to find new entries
//
// The agent is designed to be used in a slow fashion to avoid overwhelming the network.
package arp
