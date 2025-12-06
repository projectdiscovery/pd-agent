//go:build !windows

package arp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	osutils "github.com/projectdiscovery/utils/os"
)

// readLocalARPTable reads the local ARP table (Linux and macOS)
func readLocalARPTable() ([]Peer, error) {
	if osutils.IsLinux() {
		return readLinuxARPTable()
	} else if osutils.IsOSX() {
		return readDarwinARPTable()
	}
	return nil, fmt.Errorf("unsupported OS")
}

// readLinuxARPTable reads ARP table from /proc/net/arp
func readLinuxARPTable() ([]Peer, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}

	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	// Skip header line
	if !scanner.Scan() {
		return peers, nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// Format: IP address HW type Flags HW address Mask Device
		ipStr := fields[0]
		macStr := fields[3]

		// Skip incomplete entries
		if macStr == "00:00:00:00:00:00" || macStr == "<incomplete>" {
			continue
		}

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

// readDarwinARPTable reads ARP table using 'arp -a' command on macOS
func readDarwinARPTable() ([]Peer, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute arp -a: %w", err)
	}

	var peers []Peer
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// macOS arp -a format: "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ethernet] on en0"
		// or: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ethernet] on en0"

		// Extract IP address (between parentheses)
		ipStart := strings.Index(line, "(")
		ipEnd := strings.Index(line, ")")
		if ipStart == -1 || ipEnd == -1 || ipStart >= ipEnd {
			continue
		}
		ipStr := line[ipStart+1 : ipEnd]

		// Extract MAC address (after "at ")
		atIndex := strings.Index(line, " at ")
		if atIndex == -1 {
			continue
		}
		macStart := atIndex + 4
		macEnd := strings.Index(line[macStart:], " ")
		if macEnd == -1 {
			macEnd = strings.Index(line[macStart:], "[")
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
