package igmp

import (
	"net"
	"testing"

	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
)

// buildIGMPv2ReportPacket constructs a complete Ethernet+IPv4+IGMPv2-report frame.
// Returns raw bytes plus the source IP / MAC for assertions.
func buildIGMPv2ReportPacket(t *testing.T, srcIP net.IP, srcMAC net.HardwareAddr, group net.IP) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      1,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    srcIP,
		DstIP:    group,
	}
	// Build IGMPv2 report payload manually: type, max-resp, csum, group
	igmpPayload := []byte{
		IGMPV2MembershipReport, 0x00, 0x00, 0x00,
		group.To4()[0], group.To4()[1], group.To4()[2], group.To4()[3],
	}
	cs := calculateIGMPChecksum(igmpPayload)
	igmpPayload[2] = byte(cs >> 8)
	igmpPayload[3] = byte(cs & 0xff)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(igmpPayload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func TestParseIGMPPacket_V2Report(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.42").To4()
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	group := net.ParseIP("224.0.0.251").To4()

	raw := buildIGMPv2ReportPacket(t, srcIP, srcMAC, group)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	if err := pkt.ErrorLayer(); err != nil {
		t.Fatalf("decode error: %v", err.Error())
	}

	iface := &net.Interface{Name: "test0"}
	peer, err := parseIGMPPacket(pkt, iface)
	if err != nil {
		t.Fatalf("parseIGMPPacket: %v", err)
	}
	if !peer.IP.Equal(srcIP) {
		t.Errorf("peer.IP = %v, want %v", peer.IP, srcIP)
	}
	if peer.IGMPVersion != 2 {
		t.Errorf("peer.IGMPVersion = %d, want 2", peer.IGMPVersion)
	}
	if peer.MAC.String() != srcMAC.String() {
		t.Errorf("peer.MAC = %v, want %v", peer.MAC, srcMAC)
	}
	if len(peer.MulticastGroups) != 1 || peer.MulticastGroups[0] != group.String() {
		t.Errorf("peer.MulticastGroups = %v, want [%s]", peer.MulticastGroups, group)
	}
}

func TestParseIGMPPacket_RejectsQuery(t *testing.T) {
	// Build a query (type 0x11) — must be rejected, not treated as a report.
	srcIP := net.ParseIP("192.168.1.1").To4()
	srcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	group := net.ParseIP("224.0.0.1").To4()

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 1, Protocol: layers.IPProtocolIGMP, SrcIP: srcIP, DstIP: group}
	payload := buildIGMPPayload(group, 2)
	cs := calculateIGMPChecksum(payload)
	payload[2] = byte(cs >> 8)
	payload[3] = byte(cs & 0xff)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	if _, err := parseIGMPPacket(pkt, &net.Interface{Name: "test0"}); err == nil {
		t.Fatal("expected query packet to be rejected, got nil error")
	}
}

func TestParseIGMPPacket_RejectsNonIGMP(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4()}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, gopacket.Payload([]byte{0, 0, 0, 0})); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	if _, err := parseIGMPPacket(pkt, &net.Interface{Name: "test0"}); err == nil {
		t.Fatal("expected non-IGMP packet to be rejected")
	}
}

func TestParseIGMPManually_ShortPayload(t *testing.T) {
	ip := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1").To4()}
	ip.Payload = []byte{0x16, 0x00} // too short
	pkt := gopacket.NewPacket(nil, layers.LayerTypeEthernet, gopacket.Default)
	if _, err := parseIGMPManually(pkt, ip); err == nil {
		t.Fatal("expected error for short IGMP payload")
	}
}

func TestParseIGMPManually_V2Report(t *testing.T) {
	group := net.ParseIP("224.0.0.251").To4()
	ip := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1").To4()}
	ip.Payload = []byte{
		IGMPV2MembershipReport, 0x00, 0x00, 0x00,
		group[0], group[1], group[2], group[3],
	}
	pkt := gopacket.NewPacket(nil, layers.LayerTypeEthernet, gopacket.Default)
	peer, err := parseIGMPManually(pkt, ip)
	if err != nil {
		t.Fatalf("parseIGMPManually: %v", err)
	}
	if peer.IGMPVersion != 2 {
		t.Errorf("version = %d, want 2", peer.IGMPVersion)
	}
	if len(peer.MulticastGroups) != 1 || peer.MulticastGroups[0] != group.String() {
		t.Errorf("groups = %v, want [%s]", peer.MulticastGroups, group)
	}
}
