package igmp

import "testing"

func TestIsMembershipReport(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    bool
	}{
		{IGMPMembershipQuery, false},
		{IGMPV1MembershipReport, true},
		{IGMPV2MembershipReport, true},
		{IGMPV2LeaveGroup, false},
		{IGMPV3MembershipReport, true},
		{0x00, false},
		{0xff, false},
	}
	for _, tt := range tests {
		if got := IsMembershipReport(tt.msgType); got != tt.want {
			t.Errorf("IsMembershipReport(0x%02x) = %v, want %v", tt.msgType, got, tt.want)
		}
	}
}

func TestGetIGMPVersion(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    int
	}{
		{IGMPV1MembershipReport, 1},
		{IGMPV2MembershipReport, 2},
		{IGMPV2LeaveGroup, 2},
		{IGMPV3MembershipReport, 3},
		{IGMPMembershipQuery, 0},
		{0x00, 0},
	}
	for _, tt := range tests {
		if got := GetIGMPVersion(tt.msgType); got != tt.want {
			t.Errorf("GetIGMPVersion(0x%02x) = %d, want %d", tt.msgType, got, tt.want)
		}
	}
}
