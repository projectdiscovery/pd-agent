package igmp

import (
	"net"
	"testing"
)

func TestBuildIGMPPayload(t *testing.T) {
	tests := []struct {
		name    string
		group   net.IP
		version int
		want    []byte
	}{
		{
			name:    "v2 query for specific group",
			group:   net.ParseIP("224.0.0.1"),
			version: 2,
			// Type=0x11, MaxResp=100, Checksum=0,0, Group=224.0.0.1
			want: []byte{0x11, 0x64, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x01},
		},
		{
			name:    "v1 query has zero max-resp",
			group:   net.ParseIP("224.0.0.22"),
			version: 1,
			want:    []byte{0x11, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x16},
		},
		{
			name:    "general v2 query (nil group) uses 0.0.0.0",
			group:   nil,
			version: 2,
			want:    []byte{0x11, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "general v2 query (unspecified group) uses 0.0.0.0",
			group:   net.IPv4zero,
			version: 2,
			want:    []byte{0x11, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildIGMPPayload(tt.group, tt.version)
			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: got %d want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("byte %d: got 0x%02x want 0x%02x", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCalculateIGMPChecksum(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{
			// Hand-computed: words 0x1164, 0x0000, 0xe000, 0x0001
			// sum = 0x1164 + 0xe000 + 0x0001 = 0xf165
			// ^0xf165 = 0x0e9a
			name: "v2 query for 224.0.0.1",
			data: []byte{0x11, 0x64, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x01},
			want: 0x0e9a,
		},
		{
			// All zeroes -> ^0 = 0xffff
			name: "all zero payload",
			data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: 0xffff,
		},
		{
			// Force a carry: 0xffff + 0x0001 = 0x10000 -> fold to 0x0001 -> ^ = 0xfffe
			name: "carry fold",
			data: []byte{0xff, 0xff, 0x00, 0x01},
			want: 0xfffe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateIGMPChecksum(tt.data)
			if got != tt.want {
				t.Errorf("got 0x%04x want 0x%04x", got, tt.want)
			}
		})
	}
}

func TestChecksumValidates(t *testing.T) {
	// A correctly checksummed packet should sum (with checksum field included) to 0xffff.
	payload := buildIGMPPayload(net.ParseIP("224.0.0.1"), 2)
	cs := calculateIGMPChecksum(payload)
	payload[2] = byte(cs >> 8)
	payload[3] = byte(cs & 0xff)

	// Recompute over full packet including checksum field; result should be 0.
	if got := calculateIGMPChecksum(payload); got != 0 {
		t.Errorf("verification checksum got 0x%04x want 0x0000", got)
	}
}
