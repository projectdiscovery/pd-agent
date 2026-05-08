package igmp

import (
	"fmt"
	"net"
	"time"

	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
)

// parseIGMPPacket parses an IGMP packet and extracts peer information
func parseIGMPPacket(packet gopacket.Packet, iface *net.Interface) (*Peer, error) {
	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("packet does not contain IPv4 layer")
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("failed to cast to IPv4 layer")
	}

	// Check if protocol is IGMP
	if ip.Protocol != layers.IPProtocolIGMP {
		return nil, fmt.Errorf("packet is not IGMP (protocol: %d)", ip.Protocol)
	}

	// Get IGMP layer. gopacket dispatches V1/V2 frames to *layers.IGMPv1or2
	// and V3 to *layers.IGMP, so handle both. Fall back to manual parsing if
	// the layer was not produced (e.g. truncated frame).
	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		return parseIGMPManually(packet, ip)
	}

	var (
		igmpType     uint8
		groupAddress net.IP
	)
	switch v := igmpLayer.(type) {
	case *layers.IGMP:
		igmpType = uint8(v.Type)
		groupAddress = v.GroupAddress
	case *layers.IGMPv1or2:
		igmpType = uint8(v.Type)
		groupAddress = v.GroupAddress
	default:
		return nil, fmt.Errorf("unexpected IGMP layer type %T", igmpLayer)
	}

	// Only process membership reports
	if !IsMembershipReport(igmpType) {
		return nil, fmt.Errorf("not a membership report (type: 0x%02x)", igmpType)
	}

	// Extract peer information
	peer := &Peer{
		IP:              ip.SrcIP,
		LastSeen:        time.Now(),
		IGMPVersion:     GetIGMPVersion(igmpType),
		MulticastGroups: []string{},
	}

	// Extract multicast group
	if groupAddress != nil && !groupAddress.IsUnspecified() {
		peer.MulticastGroups = append(peer.MulticastGroups, groupAddress.String())
	}

	// Try to extract MAC address from Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			peer.MAC = eth.SrcMAC
		}
	}

	return peer, nil
}

// parseIGMPManually parses IGMP packet manually if gopacket layers don't support it
func parseIGMPManually(packet gopacket.Packet, ip *layers.IPv4) (*Peer, error) {
	// Get the payload (IGMP data)
	payload := ip.Payload
	if len(payload) < 8 {
		return nil, fmt.Errorf("IGMP packet too short")
	}

	// Parse IGMP header manually
	msgType := payload[0]
	maxRespTime := payload[1]
	checksum := uint16(payload[2])<<8 | uint16(payload[3])

	// Validate checksum (simplified - full validation would require recomputing)
	_ = checksum
	_ = maxRespTime

	// Only process membership reports
	if !IsMembershipReport(msgType) {
		return nil, fmt.Errorf("not a membership report (type: 0x%02x)", msgType)
	}

	// Extract group address (bytes 4-7)
	var groupAddr net.IP
	if len(payload) >= 8 {
		groupAddr = net.IP(payload[4:8])
	}

	// Create peer
	peer := &Peer{
		IP:              ip.SrcIP,
		LastSeen:        time.Now(),
		IGMPVersion:     GetIGMPVersion(msgType),
		MulticastGroups: []string{},
	}

	// Add group address if valid
	if groupAddr != nil && !groupAddr.IsUnspecified() {
		peer.MulticastGroups = append(peer.MulticastGroups, groupAddr.String())
	}

	// Try to extract MAC address from Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			peer.MAC = eth.SrcMAC
		}
	}

	return peer, nil
}
