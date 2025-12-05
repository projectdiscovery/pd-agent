//go:build !windows

package pingsweep

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// sendPing sends an ICMP echo request through the shared connection
func sendPing(conn net.PacketConn, ip net.IP, seq int, isIPv6 bool) error {
	var msgType icmp.Type

	if isIPv6 {
		msgType = ipv6.ICMPTypeEchoRequest
	} else {
		msgType = ipv4.ICMPTypeEcho
	}

	msg := &icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	dst := &net.IPAddr{IP: ip}
	_, err = conn.WriteTo(msgBytes, dst)
	return err
}

// receiveReplies receives and matches ICMP echo replies
func receiveReplies(ctx context.Context, conn net.PacketConn, pendingPings *mapsutil.SyncLockMap[int, *pendingPing], peers *mapsutil.SyncLockMap[string, *Peer], isIPv6 bool, timeout time.Duration) {
	var echoReplyType icmp.Type
	var protocol int

	if isIPv6 {
		echoReplyType = ipv6.ICMPTypeEchoReply
		protocol = ipv6.ICMPTypeEchoReply.Protocol()
	} else {
		echoReplyType = ipv4.ICMPTypeEchoReply
		protocol = ipv4.ICMPTypeEchoReply.Protocol()
	}

	expectedID := os.Getpid() & 0xffff
	// Use a longer initial deadline to match ping command behavior
	// Ping typically waits 1-2 seconds per ping, we'll use the timeout parameter
	deadline := time.Now().Add(timeout * 3) // Give more time for all pings to complete

	for {
		// Check if we should stop
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check if deadline passed
		if time.Now().After(deadline) {
			// Check if there are still pending pings
			hasPending := false
			_ = pendingPings.Iterate(func(key int, ping *pendingPing) error {
				hasPending = true
				return nil
			})
			if !hasPending {
				return
			}
			// Extend deadline if there are still pending pings - give more time
			deadline = time.Now().Add(timeout)
		}

		// Set read deadline - use longer timeout to match ping command
		// Ping command typically uses 1-2 second timeouts, we'll check more frequently but with longer socket timeout
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			continue
		}

		// Read reply
		reply := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			// Timeout or error, continue
			continue
		}

		// Parse reply
		rm, err := icmp.ParseMessage(protocol, reply[:n])
		if err != nil {
			continue
		}

		// Verify it's an echo reply
		if rm.Type != echoReplyType {
			continue
		}

		// Check if this is our reply
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// Match by ID
		if echo.ID != expectedID {
			continue
		}

		// Find matching pending ping
		pending, exists := pendingPings.Get(echo.Seq)
		if !exists {
			continue
		}

		// Verify peer IP matches
		if peerAddr, ok := peer.(*net.IPAddr); !ok || !peerAddr.IP.Equal(pending.IP) {
			continue
		}

		// Calculate RTT
		rtt := time.Since(pending.Start)

		// Store successful peer
		discoveredPeer := &Peer{
			IP:  pending.IP,
			RTT: rtt,
		}
		_ = peers.Set(pending.IP.String(), discoveredPeer)

		// Remove from pending
		pendingPings.Delete(echo.Seq)
	}
}
