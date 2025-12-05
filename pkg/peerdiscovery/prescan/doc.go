// Package prescan selects the most likely-to-be-online IPs from a CIDR based on
// real-world network patterns. Uses Pareto principle - most active hosts are in
// the top 20% of IPs (routers, gateways, early DHCP allocations).
//
// Priority tiers (0-100):
//   - 100: .1, .254 (routers/gateways - always check these first)
//   - 90:  .2-.5, .250-.253 (reserved infrastructure)
//   - 80:  .6-.10 (early DHCP - devices that connect first)
//   - 70:  .50, .100, .150 (DHCP peaks - common allocation points)
//   - 50:  .51-.99, .101-.149, .151-.200 (main DHCP pool)
//   - 20:  .11-.49, .201-.249 (long-tail, lower probability)
//   - 0:   .0, .255 (excluded - network/broadcast)
//
// Example:
//
//	// Get top 25% most likely IPs
//	ips, err := prescan.SelectIPs("192.168.1.0/24", 0.25)
//
//	// Or get exactly 50 IPs
//	ips, err := prescan.SelectIPsWithCount("192.168.1.0/24", 50)
//
// O(n log n) complexity. For huge networks, use SelectIPsWithCount.
package prescan

