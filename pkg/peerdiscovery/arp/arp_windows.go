//go:build windows

package arp

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// readLocalARPTable reads the local ARP table on Windows using 'arp -a' command
func readLocalARPTable() ([]Peer, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute arp -a: %w", err)
	}

	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Windows arp -a output has two sections: Interface and ARP entries
	// Format example:
	// Interface: 192.168.1.100 --- 0xa
	//   Internet Address      Physical Address      Type
	//   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
	//   192.168.1.255         ff-ff-ff-ff-ff-ff     static

	inARPTable := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check if we're entering the ARP table section
		if strings.Contains(line, "Internet Address") && strings.Contains(line, "Physical Address") {
			inARPTable = true
			continue
		}

		// Check if we're entering a new interface section
		if strings.HasPrefix(line, "Interface:") {
			inARPTable = false
			continue
		}

		if !inARPTable {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ipStr := fields[0]
		macStr := fields[1]

		// Skip incomplete entries
		if macStr == "incomplete" || strings.HasPrefix(macStr, "ff-ff-ff-ff-ff-ff") {
			continue
		}

		// Convert Windows MAC format (aa-bb-cc-dd-ee-ff) to standard format (aa:bb:cc:dd:ee:ff)
		macStr = strings.ReplaceAll(macStr, "-", ":")

		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}

		mac, err := net.ParseMAC(macStr)
		if err != nil {
			continue
		}

		peers = append(peers, Peer{
			IP:  ip,
			MAC: mac,
		})
	}

	return peers, scanner.Err()
}
