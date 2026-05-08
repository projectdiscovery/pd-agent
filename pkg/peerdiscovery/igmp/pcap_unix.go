//go:build !windows

package igmp

import "github.com/Mzack9999/gopacket/pcap"

// loadPcap dlopens libpcap. Result is cached inside Mzack9999/gopacket/pcap,
// so repeated calls are cheap.
func loadPcap() error {
	return pcap.LoadUnixPCAP()
}
