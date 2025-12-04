//go:build windows

package ndp

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// readLocalNDPTable reads the local NDP table on Windows using 'netsh interface ipv6 show neighbors' command
func readLocalNDPTable() ([]Peer, error) {
	cmd := exec.Command("netsh", "interface", "ipv6", "show", "neighbors")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute netsh interface ipv6 show neighbors: %w", err)
	}

	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Windows netsh output format:
	// Interface 12: Ethernet
	// fe80::1    aa-bb-cc-dd-ee-ff    Permanent
	// 2001:db8::1    aa-bb-cc-dd-ee-ff    Reachable

	inTable := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check if we're entering the neighbors table
		if strings.Contains(line, "Interface") {
			inTable = true
			continue
		}

		if !inTable {
			continue
		}

		// Skip header lines
		if strings.Contains(line, "IPv6 Address") || strings.Contains(line, "---") {
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
		if ip == nil {
			continue
		}

		// Only process IPv6 addresses
		if ip.To4() != nil {
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

