package igmp

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	// DefaultSnapLen is the default snapshot length for packet capture
	DefaultSnapLen = 1600
	// DefaultPromisc enables promiscuous mode by default
	DefaultPromisc = true
	// DefaultTimeout is the default timeout for packet reads (100ms for responsiveness)
	DefaultTimeout = 100 * time.Millisecond
)

// createCaptureHandle creates a pcap handle for packet capture on the given interface
func createCaptureHandle(iface *net.Interface, config *Config) (*pcap.Handle, error) {
	// Open live capture with timeout for responsive context cancellation
	handle, err := pcap.OpenLive(iface.Name, DefaultSnapLen, DefaultPromisc, DefaultTimeout)
	if err != nil {
		return nil, err
	}

	return handle, nil
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
