//go:build !windows

package ndp

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	osutils "github.com/projectdiscovery/utils/os"
)

// readLocalNDPTable reads the local NDP table (Linux and macOS)
func readLocalNDPTable() ([]Peer, error) {
	if osutils.IsLinux() {
		return readLinuxNDPTable()
	} else if osutils.IsOSX() {
		return readDarwinNDPTable()
	}
	return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

// readLinuxNDPTable reads NDP table using 'ip -6 neigh show' command on Linux
func readLinuxNDPTable() ([]Peer, error) {
	cmd := exec.Command("ip", "-6", "neigh", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute ip -6 neigh show: %w", err)
	}

	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Format: fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
		// or: fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
		ipStr := fields[0]

		// Find MAC address (field with lladdr prefix or after lladdr)
		var macStr string
		for i, field := range fields {
			if field == "lladdr" && i+1 < len(fields) {
				macStr = fields[i+1]
				break
			}
		}

		if macStr == "" {
			continue
		}

		// Skip incomplete entries
		if macStr == "00:00:00:00:00:00" || strings.Contains(line, "FAILED") {
			continue
		}

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

// readDarwinNDPTable reads NDP table using 'ndp -an' command on macOS
func readDarwinNDPTable() ([]Peer, error) {
	cmd := exec.Command("ndp", "-an")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute ndp -an: %w", err)
	}

	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// macOS ndp -an format: "? (fe80::1%en0) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
		// or: "fe80::1%en0 (fe80::1%en0) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
		
		// Extract IP address (between parentheses, before % if present)
		ipStart := strings.Index(line, "(")
		ipEnd := strings.Index(line, ")")
		if ipStart == -1 || ipEnd == -1 || ipStart >= ipEnd {
			continue
		}
		ipWithScope := line[ipStart+1 : ipEnd]

		// Remove scope identifier (%interface)
		ipStr := ipWithScope
		if scopeIdx := strings.Index(ipWithScope, "%"); scopeIdx != -1 {
			ipStr = ipWithScope[:scopeIdx]
		}

		// Extract MAC address (after "at ")
		atIndex := strings.Index(line, " at ")
		if atIndex == -1 {
			continue
		}
		macStart := atIndex + 4
		macEnd := strings.Index(line[macStart:], " ")
		if macEnd == -1 {
			macEnd = strings.Index(line[macStart:], " on")
		}
		if macEnd == -1 {
			macEnd = len(line) - macStart
		}
		macStr := strings.TrimSpace(line[macStart : macStart+macEnd])

		// Skip incomplete entries
		if macStr == "(incomplete)" || macStr == "" {
			continue
		}

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

