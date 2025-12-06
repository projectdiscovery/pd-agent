package igmp

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

// sendMembershipQuery sends an IGMP membership query to the specified multicast group
func sendMembershipQuery(iface *net.Interface, group net.IP, version int) error {
	// Get interface IP
	srcIP := getInterfaceIP(iface)
	if srcIP == nil || srcIP.IsUnspecified() {
		return fmt.Errorf("interface %s has no IPv4 address", iface.Name)
	}

	// Build IGMP payload
	igmpPayload := buildIGMPPayload(group, version)

	// Create raw socket for sending
	conn, err := net.ListenPacket("ip4:2", "0.0.0.0") // Protocol 2 = IGMP
	if err != nil {
		return fmt.Errorf("failed to create raw socket: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Wrap with ipv4.RawConn for control
	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		return fmt.Errorf("failed to create raw connection: %w", err)
	}
	defer func() {
		_ = rawConn.Close()
	}()

	// Set socket options
	if err := rawConn.SetMulticastInterface(iface); err != nil {
		return fmt.Errorf("failed to set multicast interface: %w", err)
	}

	// Build IP header using gopacket for proper construction
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5, // 20 bytes header (5 * 4)
		TTL:      1, // Don't route beyond local network
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    srcIP,
		DstIP:    group,
	}

	// Serialize IP header to get proper values
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, gopacket.Payload(igmpPayload)); err != nil {
		return fmt.Errorf("failed to serialize IP layer: %w", err)
	}

	packetBytes := buffer.Bytes()

	// Calculate and set IGMP checksum
	igmpStart := 20 // IP header length
	if len(packetBytes) >= igmpStart+8 {
		checksum := calculateIGMPChecksum(packetBytes[igmpStart : igmpStart+8])
		packetBytes[igmpStart+2] = byte(checksum >> 8)
		packetBytes[igmpStart+3] = byte(checksum & 0xff)
	}

	// Extract IP header and IGMP payload for raw socket
	ipHeader := &ipv4.Header{
		Version:  int(packetBytes[0] >> 4),
		Len:      int((packetBytes[0] & 0x0f) * 4),
		TotalLen: int(uint16(packetBytes[2])<<8 | uint16(packetBytes[3])),
		TTL:      int(packetBytes[8]),
		Protocol: int(packetBytes[9]),
		Src:      net.IP(packetBytes[12:16]),
		Dst:      net.IP(packetBytes[16:20]),
	}

	igmpData := packetBytes[20:]

	// Set control flags
	cm := &ipv4.ControlMessage{
		IfIndex: iface.Index,
	}

	// Send packet
	if err := rawConn.WriteTo(ipHeader, igmpData, cm); err != nil {
		return fmt.Errorf("failed to send IGMP query: %w", err)
	}

	return nil
}

// buildIGMPPayload constructs the IGMP payload (without IP header)
func buildIGMPPayload(group net.IP, version int) []byte {
	// IGMP query packet structure:
	// Type (1 byte) + Max Response Time (1 byte) + Checksum (2 bytes) + Group Address (4 bytes)
	data := make([]byte, 8)

	// Type: Membership Query
	data[0] = IGMPMembershipQuery

	// Max Response Time (in 1/10 second units for IGMPv2)
	// Default: 10 seconds = 100 (0x64)
	if version == 2 {
		data[1] = 100 // 10 seconds
	} else {
		data[1] = 0 // IGMPv1 uses 0
	}

	// Checksum (will be calculated after IP header is known)
	data[2] = 0
	data[3] = 0

	// Group Address
	if group != nil && !group.IsUnspecified() {
		copy(data[4:8], group.To4())
	} else {
		// General query uses 0.0.0.0
		copy(data[4:8], net.IPv4zero.To4())
	}

	return data
}

// calculateIGMPChecksum calculates the IGMP checksum (RFC 1071)
// The checksum is the 16-bit one's complement of the one's complement sum
// of all 16-bit words in the IGMP message.
func calculateIGMPChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data); i += 2 {
		var word uint16
		if i+1 < len(data) {
			word = uint16(data[i])<<8 | uint16(data[i+1])
		} else {
			word = uint16(data[i]) << 8
		}
		sum += uint32(word)
	}

	// Add carry bits (fold 32-bit sum to 16 bits)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// One's complement
	return ^uint16(sum)
}

// getInterfaceIP gets the first IPv4 address of an interface
func getInterfaceIP(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				// Skip link-local addresses (169.254.0.0/16)
				if !ip.IsLinkLocalUnicast() {
					return ip
				}
			}
		}
	}

	// Fallback to any IPv4 address if no non-link-local found
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				return ip
			}
		}
	}

	return nil
}
