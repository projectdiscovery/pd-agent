package igmp

import "net"

// CommonMulticastGroups contains commonly used multicast group addresses
var CommonMulticastGroups = []net.IP{
	net.ParseIP("224.0.0.1"),       // All Systems (all-hosts)
	net.ParseIP("224.0.0.2"),       // All Routers
	net.ParseIP("224.0.0.22"),      // IGMP
	net.ParseIP("224.0.0.251"),     // mDNS
	net.ParseIP("224.0.0.252"),     // LLMNR
	net.ParseIP("239.255.255.250"), // SSDP
}

// IGMP message type constants
const (
	IGMPMembershipQuery    = 0x11 // Membership query
	IGMPV1MembershipReport = 0x12 // IGMPv1 membership report
	IGMPV2MembershipReport = 0x16 // IGMPv2 membership report
	IGMPV2LeaveGroup       = 0x17 // IGMPv2 leave group
	IGMPV3MembershipReport = 0x22 // IGMPv3 membership report
)

// IsMembershipReport checks if the IGMP type is a membership report
func IsMembershipReport(msgType uint8) bool {
	return msgType == IGMPV1MembershipReport ||
		msgType == IGMPV2MembershipReport ||
		msgType == IGMPV3MembershipReport
}

// GetIGMPVersion returns the IGMP version based on message type
func GetIGMPVersion(msgType uint8) int {
	switch msgType {
	case IGMPV1MembershipReport:
		return 1
	case IGMPV2MembershipReport, IGMPV2LeaveGroup:
		return 2
	case IGMPV3MembershipReport:
		return 3
	default:
		return 0
	}
}
