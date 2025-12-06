package prescan

import (
	"net"
	"testing"

	"github.com/projectdiscovery/pd-agent/pkg/peerdiscovery/common"
)

func TestSelectIPs(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		ratio     float64
		wantCount int
		wantErr   bool
		validate  func(t *testing.T, ips []net.IP)
	}{
		{
			name:      "25% of /24 network",
			cidr:      "192.168.1.0/24",
			ratio:     0.25,
			wantCount: 64, // 254 usable IPs * 0.25 = 63.5, rounded up to 64
			wantErr:   false,
			validate: func(t *testing.T, ips []net.IP) {
				// Should include high-priority IPs
				has1 := false
				has254 := false
				for _, ip := range ips {
					ip4 := ip.To4()
					if ip4 != nil && ip4[3] == 1 {
						has1 = true
					}
					if ip4 != nil && ip4[3] == 254 {
						has254 = true
					}
				}
				if !has1 {
					t.Error("Expected to include .1 (router)")
				}
				if !has254 {
					t.Error("Expected to include .254 (gateway)")
				}
			},
		},
		{
			name:      "50% of /24 network",
			cidr:      "192.168.1.0/24",
			ratio:     0.5,
			wantCount: 127, // 254 usable IPs * 0.5 = 127
			wantErr:   false,
		},
		{
			name:      "100% of /24 network",
			cidr:      "192.168.1.0/24",
			ratio:     1.0,
			wantCount: 254, // All usable IPs
			wantErr:   false,
		},
		{
			name:      "0% ratio",
			cidr:      "192.168.1.0/24",
			ratio:     0.0,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "10% of /24 network",
			cidr:      "192.168.1.0/24",
			ratio:     0.1,
			wantCount: 26, // 254 * 0.1 = 25.4, rounded up
			wantErr:   false,
			validate: func(t *testing.T, ips []net.IP) {
				// Should prioritize high-priority IPs
				// Check that .1 and .254 are included
				has1 := false
				has254 := false
				for _, ip := range ips {
					ip4 := ip.To4()
					if ip4 != nil && ip4[3] == 1 {
						has1 = true
					}
					if ip4 != nil && ip4[3] == 254 {
						has254 = true
					}
				}
				if !has1 {
					t.Error("Expected to include .1 in top 10%")
				}
				if !has254 {
					t.Error("Expected to include .254 in top 10%")
				}
			},
		},
		{
			name:      "Invalid CIDR",
			cidr:      "invalid",
			ratio:     0.25,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "Single host /32",
			cidr:      "192.168.1.1/32",
			ratio:     0.5,
			wantCount: 0, // /32 has no usable IPs (network = broadcast)
			wantErr:   false,
		},
		{
			name:      "Negative ratio clamped to 0",
			cidr:      "192.168.1.0/24",
			ratio:     -0.1,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "Ratio > 1 clamped to 1",
			cidr:      "192.168.1.0/24",
			ratio:     1.5,
			wantCount: 254,
			wantErr:   false,
		},
		{
			name:      "Small /30 network",
			cidr:      "192.168.1.0/30",
			ratio:     0.5,
			wantCount: 1, // 2 usable IPs * 0.5 = 1
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := SelectIPs(tt.cidr, tt.ratio)
			if (err != nil) != tt.wantErr {
				t.Errorf("SelectIPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(ips) != tt.wantCount {
				t.Errorf("SelectIPs() count = %d, want %d", len(ips), tt.wantCount)
			}
			if tt.validate != nil {
				tt.validate(t, ips)
			}
		})
	}
}

func TestSelectIPsWithCount(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		count    int
		wantErr  bool
		validate func(t *testing.T, ips []net.IP)
	}{
		{
			name:    "Select 50 IPs from /24",
			cidr:    "192.168.1.0/24",
			count:   50,
			wantErr: false,
			validate: func(t *testing.T, ips []net.IP) {
				if len(ips) != 50 {
					t.Errorf("Expected 50 IPs, got %d", len(ips))
				}
				// Should include high-priority IPs
				has1 := false
				has254 := false
				for _, ip := range ips {
					ip4 := ip.To4()
					if ip4 != nil && ip4[3] == 1 {
						has1 = true
					}
					if ip4 != nil && ip4[3] == 254 {
						has254 = true
					}
				}
				if !has1 {
					t.Error("Expected to include .1")
				}
				if !has254 {
					t.Error("Expected to include .254")
				}
			},
		},
		{
			name:    "Select 0 IPs",
			cidr:    "192.168.1.0/24",
			count:   0,
			wantErr: false,
			validate: func(t *testing.T, ips []net.IP) {
				if len(ips) != 0 {
					t.Errorf("Expected 0 IPs, got %d", len(ips))
				}
			},
		},
		{
			name:    "Select more than available",
			cidr:    "192.168.1.0/24",
			count:   1000,
			wantErr: false,
			validate: func(t *testing.T, ips []net.IP) {
				// Should return all usable IPs (254)
				if len(ips) != 254 {
					t.Errorf("Expected 254 IPs, got %d", len(ips))
				}
			},
		},
		{
			name:    "Invalid CIDR",
			cidr:    "invalid",
			count:   10,
			wantErr: true,
		},
		{
			name:    "Single host /32",
			cidr:    "192.168.1.1/32",
			count:   10,
			wantErr: false,
			validate: func(t *testing.T, ips []net.IP) {
				// /32 has no usable IPs (network = broadcast)
				if len(ips) != 0 {
					t.Errorf("Expected 0 IPs for /32, got %d", len(ips))
				}
			},
		},
		{
			name:    "Negative count",
			cidr:    "192.168.1.0/24",
			count:   -5,
			wantErr: false,
			validate: func(t *testing.T, ips []net.IP) {
				if len(ips) != 0 {
					t.Errorf("Expected 0 IPs for negative count, got %d", len(ips))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := SelectIPsWithCount(tt.cidr, tt.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("SelectIPsWithCount() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.validate != nil {
				tt.validate(t, ips)
			}
		})
	}
}

func TestCalculatePriority(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	tests := []struct {
		name    string
		ip      string
		network *net.IPNet
		want    int
		wantErr bool
	}{
		{
			name:    "Infrastructure .1",
			ip:      "192.168.1.1",
			network: network,
			want:    PriorityTier1,
		},
		{
			name:    "Infrastructure .254",
			ip:      "192.168.1.254",
			network: network,
			want:    PriorityTier1,
		},
		{
			name:    "Reserved .2",
			ip:      "192.168.1.2",
			network: network,
			want:    PriorityTier2,
		},
		{
			name:    "Reserved .5",
			ip:      "192.168.1.5",
			network: network,
			want:    PriorityTier2,
		},
		{
			name:    "Reserved .250",
			ip:      "192.168.1.250",
			network: network,
			want:    PriorityTier2,
		},
		{
			name:    "Early DHCP .6",
			ip:      "192.168.1.6",
			network: network,
			want:    PriorityTier3,
		},
		{
			name:    "Early DHCP .10",
			ip:      "192.168.1.10",
			network: network,
			want:    PriorityTier3,
		},
		{
			name:    "DHCP peak .50",
			ip:      "192.168.1.50",
			network: network,
			want:    PriorityTier4,
		},
		{
			name:    "DHCP peak .100",
			ip:      "192.168.1.100",
			network: network,
			want:    PriorityTier4,
		},
		{
			name:    "DHCP peak .150",
			ip:      "192.168.1.150",
			network: network,
			want:    PriorityTier4,
		},
		{
			name:    "DHCP range .51",
			ip:      "192.168.1.51",
			network: network,
			want:    PriorityTier5,
		},
		{
			name:    "DHCP range .200",
			ip:      "192.168.1.200",
			network: network,
			want:    PriorityTier5,
		},
		{
			name:    "Long-tail .25",
			ip:      "192.168.1.25",
			network: network,
			want:    PriorityTier6,
		},
		{
			name:    "Long-tail .240",
			ip:      "192.168.1.240",
			network: network,
			want:    PriorityTier6,
		},
		{
			name:    "Network address .0",
			ip:      "192.168.1.0",
			network: network,
			want:    PriorityTier7,
		},
		{
			name:    "Broadcast address .255",
			ip:      "192.168.1.255",
			network: network,
			want:    PriorityTier7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			got := CalculatePriority(ip, tt.network)
			if got != tt.want {
				t.Errorf("CalculatePriority() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPriorityOrdering(t *testing.T) {
	// Test that SelectIPs returns IPs in priority order
	ips, err := SelectIPs("192.168.1.0/24", 0.5)
	if err != nil {
		t.Fatalf("SelectIPs() error = %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("Expected at least some IPs")
	}

	// Calculate priorities for all returned IPs
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	priorities := make([]int, len(ips))
	for i, ip := range ips {
		priorities[i] = CalculatePriority(ip, network)
	}

	// Check that priorities are in descending order
	for i := 1; i < len(priorities); i++ {
		if priorities[i] > priorities[i-1] {
			t.Errorf("IPs not in priority order: priority[%d]=%d > priority[%d]=%d",
				i, priorities[i], i-1, priorities[i-1])
		}
	}
}

func TestHighPriorityIPsIncluded(t *testing.T) {
	// Test that high-priority IPs are included even in small ratios
	ips, err := SelectIPs("192.168.1.0/24", 0.05) // 5% = ~13 IPs
	if err != nil {
		t.Fatalf("SelectIPs() error = %v", err)
	}

	// Check for high-priority IPs
	has1 := false
	has254 := false
	has2to5 := false
	has250to253 := false

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		lastOctet := ip4[3]

		if lastOctet == 1 {
			has1 = true
		}
		if lastOctet == 254 {
			has254 = true
		}
		if lastOctet >= 2 && lastOctet <= 5 {
			has2to5 = true
		}
		if lastOctet >= 250 && lastOctet <= 253 {
			has250to253 = true
		}
	}

	if !has1 {
		t.Error("Expected .1 to be included in top 5%")
	}
	if !has254 {
		t.Error("Expected .254 to be included in top 5%")
	}
	if !has2to5 {
		t.Error("Expected some .2-.5 IPs to be included in top 5%")
	}
	if !has250to253 {
		t.Error("Expected some .250-.253 IPs to be included in top 5%")
	}
}

func TestDHCPPeaksIncluded(t *testing.T) {
	// Test that DHCP peaks are included in reasonable ratios
	ips, err := SelectIPs("192.168.1.0/24", 0.15) // 15% = ~38 IPs
	if err != nil {
		t.Fatalf("SelectIPs() error = %v", err)
	}

	has50 := false
	has100 := false
	has150 := false

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		lastOctet := ip4[3]

		if lastOctet == 50 {
			has50 = true
		}
		if lastOctet == 100 {
			has100 = true
		}
		if lastOctet == 150 {
			has150 = true
		}
	}

	if !has50 {
		t.Error("Expected .50 to be included in top 15%")
	}
	if !has100 {
		t.Error("Expected .100 to be included in top 15%")
	}
	if !has150 {
		t.Error("Expected .150 to be included in top 15%")
	}
}

func TestNetworkAndBroadcastExcluded(t *testing.T) {
	ips, err := SelectIPs("192.168.1.0/24", 1.0) // 100% should include all but .0 and .255
	if err != nil {
		t.Fatalf("SelectIPs() error = %v", err)
	}

	has0 := false
	has255 := false

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		lastOctet := ip4[3]

		if lastOctet == 0 {
			has0 = true
		}
		if lastOctet == 255 {
			has255 = true
		}
	}

	if has0 {
		t.Error("Network address .0 should be excluded")
	}
	if has255 {
		t.Error("Broadcast address .255 should be excluded")
	}
}

func TestDifferentSubnetSizes(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		ratio   float64
		wantMin int
		wantMax int
	}{
		{
			name:    "/30 network",
			cidr:    "192.168.1.0/30",
			ratio:   0.5,
			wantMin: 1,
			wantMax: 2,
		},
		{
			name:    "/28 network",
			cidr:    "192.168.1.0/28",
			ratio:   0.5,
			wantMin: 7,
			wantMax: 14,
		},
		{
			name:    "/25 network",
			cidr:    "192.168.1.0/25",
			ratio:   0.5,
			wantMin: 63,
			wantMax: 126,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := SelectIPs(tt.cidr, tt.ratio)
			if err != nil {
				t.Fatalf("SelectIPs() error = %v", err)
			}
			if len(ips) < tt.wantMin || len(ips) > tt.wantMax {
				t.Errorf("SelectIPs() count = %d, want between %d and %d", len(ips), tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCompareIP(t *testing.T) {
	tests := []struct {
		name string
		ip1  string
		ip2  string
		want int
	}{
		{
			name: "ip1 < ip2",
			ip1:  "192.168.1.1",
			ip2:  "192.168.1.2",
			want: -1,
		},
		{
			name: "ip1 > ip2",
			ip1:  "192.168.1.2",
			ip2:  "192.168.1.1",
			want: 1,
		},
		{
			name: "ip1 == ip2",
			ip1:  "192.168.1.1",
			ip2:  "192.168.1.1",
			want: 0,
		},
		{
			name: "Different first octet",
			ip1:  "192.168.1.1",
			ip2:  "193.168.1.1",
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip1 := net.ParseIP(tt.ip1)
			ip2 := net.ParseIP(tt.ip2)
			got := compareIP(ip1, ip2)
			if got != tt.want {
				t.Errorf("compareIP() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDeterministicOrdering(t *testing.T) {
	// Test that the same input produces the same output
	ips1, err1 := SelectIPs("192.168.1.0/24", 0.25)
	ips2, err2 := SelectIPs("192.168.1.0/24", 0.25)

	if err1 != nil || err2 != nil {
		t.Fatalf("SelectIPs() errors: %v, %v", err1, err2)
	}

	if len(ips1) != len(ips2) {
		t.Fatalf("Different lengths: %d vs %d", len(ips1), len(ips2))
	}

	for i := range ips1 {
		if !ips1[i].Equal(ips2[i]) {
			t.Errorf("Different IPs at index %d: %s vs %s", i, ips1[i], ips2[i])
		}
	}
}

func BenchmarkSelectIPs(b *testing.B) {
	cidr := "192.168.1.0/24"
	ratio := 0.25

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SelectIPs(cidr, ratio)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSelectIPsWithCount(b *testing.B) {
	cidr := "192.168.1.0/24"
	count := 50

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SelectIPsWithCount(cidr, count)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCalculatePriority(b *testing.B) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	ip := net.ParseIP("192.168.1.100")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculatePriority(ip, network)
	}
}

func TestCalculatePriorityNilNetwork(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	priority := CalculatePriority(ip, nil)
	if priority != PriorityTier6 {
		t.Errorf("Expected default priority %d for nil network, got %d", PriorityTier6, priority)
	}
}

func TestCalculatePriorityIPv6(t *testing.T) {
	_, network, _ := net.ParseCIDR("2001:db8::/32")
	ip := net.ParseIP("2001:db8::1")
	priority := CalculatePriority(ip, network)
	// IPv6 should get default priority
	if priority != PriorityTier6 {
		t.Errorf("Expected default priority %d for IPv6, got %d", PriorityTier6, priority)
	}
}

func TestCompareIPIPv6(t *testing.T) {
	ip1 := net.ParseIP("2001:db8::1")
	ip2 := net.ParseIP("2001:db8::2")

	result := compareIP(ip1, ip2)
	if result >= 0 {
		t.Errorf("Expected ip1 < ip2 for IPv6, got %d", result)
	}
}

func TestCompareIPMixed(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("2001:db8::1")

	// IPv4 should come before IPv6
	result := compareIP(ip1, ip2)
	if result >= 0 {
		t.Errorf("Expected IPv4 < IPv6, got %d", result)
	}

	// Reverse order
	result = compareIP(ip2, ip1)
	if result <= 0 {
		t.Errorf("Expected IPv6 > IPv4, got %d", result)
	}
}

func TestAdaptPriorityForSubnet(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		ip      string
		wantNot int // Should not be this priority (excluded)
	}{
		{
			name:    "/25 network",
			cidr:    "192.168.1.0/25",
			ip:      "192.168.1.1",
			wantNot: PriorityTier7, // Should not be excluded
		},
		{
			name:    "/16 network",
			cidr:    "192.168.0.0/16",
			ip:      "192.168.1.1",
			wantNot: PriorityTier7, // Should not be excluded
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, network, _ := net.ParseCIDR(tt.cidr)
			ip := net.ParseIP(tt.ip)
			priority := adaptPriorityForSubnet(ip, network)
			if priority == tt.wantNot {
				t.Errorf("Priority should not be %d for %s in %s", tt.wantNot, tt.ip, tt.cidr)
			}
		})
	}
}

func TestFilterUsableIPs(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	ips := []string{
		"192.168.1.0",   // Network - should be filtered
		"192.168.1.1",   // Usable
		"192.168.1.255", // Broadcast - should be filtered
		"192.168.1.100", // Usable
		"invalid",       // Invalid - should be filtered
	}

	usable := filterUsableIPs(ips, network)

	if len(usable) != 2 {
		t.Errorf("Expected 2 usable IPs, got %d", len(usable))
	}

	// Check that .0 and .255 are not included
	for _, ip := range usable {
		ip4 := ip.To4()
		if ip4 != nil {
			if ip4[3] == 0 || ip4[3] == 255 {
				t.Errorf("Network/broadcast address should be filtered: %s", ip)
			}
		}
	}
}

func TestIsNetworkOrBroadcast(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "Network address",
			ip:   "192.168.1.0",
			want: true,
		},
		{
			name: "Broadcast address",
			ip:   "192.168.1.255",
			want: true,
		},
		{
			name: "Regular IP",
			ip:   "192.168.1.1",
			want: false,
		},
		{
			name: "Another regular IP",
			ip:   "192.168.1.100",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := common.IsNetworkOrBroadcast(ip, network)
			if got != tt.want {
				t.Errorf("IsNetworkOrBroadcast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectIPsEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		ratio    float64
		validate func(t *testing.T, ips []net.IP, err error)
	}{
		{
			name:  "Very small ratio",
			cidr:  "192.168.1.0/24",
			ratio: 0.001, // 0.1%
			validate: func(t *testing.T, ips []net.IP, err error) {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				// Should get at least 1 IP
				if len(ips) < 1 {
					t.Error("Expected at least 1 IP for very small ratio")
				}
			},
		},
		{
			name:  "Exact 50%",
			cidr:  "192.168.1.0/24",
			ratio: 0.5,
			validate: func(t *testing.T, ips []net.IP, err error) {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				// Should get approximately 127 IPs (254 * 0.5)
				if len(ips) < 120 || len(ips) > 130 {
					t.Errorf("Expected approximately 127 IPs for 50%% ratio, got %d", len(ips))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := SelectIPs(tt.cidr, tt.ratio)
			tt.validate(t, ips, err)
		})
	}
}
