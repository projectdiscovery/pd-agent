package igmp

import (
	"net"
	"time"

	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/pcap"
)

const (
	// DefaultSnapLen is the default snapshot length for packet capture
	DefaultSnapLen = 1600
	// DefaultPromisc enables promiscuous mode by default
	DefaultPromisc = true
	// DefaultTimeout is the default timeout for packet reads (100ms for responsiveness)
	DefaultTimeout = 100 * time.Millisecond
)

// createCaptureHandle creates a pcap handle for packet capture on the given interface.
// Callers must ensure libpcap is loadable (see DiscoverPeers' upfront loadPcap check);
// otherwise pcap.OpenLive returns an error.
func createCaptureHandle(iface *net.Interface, config *Config) (*pcap.Handle, error) {
	return pcap.OpenLive(iface.Name, DefaultSnapLen, DefaultPromisc, DefaultTimeout)
}

// packetSource wraps pcap packet source
type packetSource struct {
	source *gopacket.PacketSource
	handle *pcap.Handle
}

// newPacketSource creates a new packet source from a pcap handle
func newPacketSource(handle *pcap.Handle) *packetSource {
	return &packetSource{
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
		handle: handle,
	}
}
