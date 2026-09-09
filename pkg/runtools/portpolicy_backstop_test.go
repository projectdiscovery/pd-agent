package runtools

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// listenCounting binds loopback and counts bytes received. denied=true picks
// the first free port in 9100-9107 (skips when none is free); denied=false
// picks an ephemeral port as the control that proves bytes are observable.
func listenCounting(t *testing.T, denied bool) (addr string, received *atomic.Int64, stop func()) {
	t.Helper()
	var ln net.Listener
	var err error
	if denied {
		for p := 9100; p <= 9107; p++ {
			ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
			if err == nil {
				break
			}
		}
		if err != nil {
			t.Skipf("no denied port free on loopback: %v", err)
		}
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen control port: %v", err)
		}
	}
	received = new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				for {
					n, err := c.Read(buf)
					received.Add(int64(n))
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), received, func() { _ = ln.Close() }
}

// The list filter in pkg/execute.go is the primary gate; these prove the
// tool-level backstops hold even when a denied host:port is fed directly.
func TestRunHttpx_BackstopNeverSendsToDeniedPort(t *testing.T) {
	for _, tc := range []struct {
		name      string
		denied    bool
		wantBytes bool
	}{
		{"control port receives bytes", false, true},
		{"denied port receives nothing", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, received, stop := listenCounting(t, tc.denied)
			defer stop()

			out := filepath.Join(t.TempDir(), "httpx.jsonl")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, _, err := RunHttpx(ctx, []string{addr}, HttpxOptions{OutputFile: out, DisableStdout: true, Timeout: 2 * time.Second}); err != nil {
				t.Fatalf("RunHttpx: %v", err)
			}
			if got := received.Load(); (got > 0) != tc.wantBytes {
				t.Fatalf("httpx sent %d bytes to %s, wantBytes=%v", got, addr, tc.wantBytes)
			}
		})
	}
}

func TestRunTlsx_BackstopNeverSendsToDeniedPort(t *testing.T) {
	for _, tc := range []struct {
		name      string
		denied    bool
		wantBytes bool
	}{
		{"control port receives bytes", false, true},
		{"denied port receives nothing", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, received, stop := listenCounting(t, tc.denied)
			defer stop()

			out := filepath.Join(t.TempDir(), "tlsx.jsonl")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, err := RunTlsx(ctx, []string{addr}, TlsxOptions{OutputFile: out, Timeout: 2 * time.Second, Retries: 1}); err != nil {
				t.Fatalf("RunTlsx: %v", err)
			}
			if got := received.Load(); (got > 0) != tc.wantBytes {
				t.Fatalf("tlsx sent %d bytes to %s, wantBytes=%v", got, addr, tc.wantBytes)
			}
		})
	}
}

// naabu must not even complete a TCP handshake on a denied port, whether the
// port comes from the port spec or rides on the input as host:port.
func TestRunNaabu_NeverConnectsToDeniedPort(t *testing.T) {
	deniedAddr, deniedConns, stopDenied := listenConnCounting(t, true)
	defer stopDenied()
	controlAddr, controlConns, stopControl := listenConnCounting(t, false)
	defer stopControl()
	_, deniedPort, _ := net.SplitHostPort(deniedAddr)
	_, controlPort, _ := net.SplitHostPort(controlAddr)

	out := filepath.Join(t.TempDir(), "naabu.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := RunNaabu(ctx, []string{"127.0.0.1", deniedAddr}, NaabuOptions{
		OutputFile:        out,
		SkipHostDiscovery: true,
		Ports:             deniedPort + "," + controlPort,
	})
	if err != nil {
		t.Logf("RunNaabu returned %v (non-fatal: naabu errors when nothing is open)", err)
	}
	if got := controlConns.Load(); got == 0 {
		t.Skipf("naabu did not reach the loopback control port (unprivileged/loopback limits); cannot prove anything here")
	}
	if got := deniedConns.Load(); got != 0 {
		t.Fatalf("naabu opened %d connection(s) to denied port %s", got, deniedAddr)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), ":"+deniedPort) {
		t.Fatalf("denied port reached output (inventory): %s", data)
	}
}

func TestRunNaabu_WhitespaceDeniedTargetNeverConnects(t *testing.T) {
	deniedAddr, deniedConns, stopDenied := listenConnCounting(t, true)
	defer stopDenied()
	controlAddr, controlConns, stopControl := listenConnCounting(t, false)
	defer stopControl()
	out := filepath.Join(t.TempDir(), "naabu.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// TopPorts leaves naabu's per-target port path active, unlike a literal
	// Ports list. A padded denied target must not escape through that path.
	_, err := RunNaabu(ctx, []string{deniedAddr + " \t", controlAddr}, NaabuOptions{
		OutputFile: out, SkipHostDiscovery: true, Ports: "top-100",
	})
	if err != nil {
		t.Fatalf("RunNaabu: %v", err)
	}
	if got := deniedConns.Load(); got != 0 {
		t.Fatalf("naabu opened %d connections to padded denied target %s", got, deniedAddr)
	}
	if controlConns.Load() == 0 {
		t.Fatal("naabu did not reach the allowed control target")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), deniedAddr) {
		t.Fatalf("denied target reached inventory output: %s", data)
	}
	if !strings.Contains(string(data), controlAddr) {
		t.Fatalf("allowed control target missing from output: %s", data)
	}
}

func listenConnCounting(t *testing.T, denied bool) (addr string, conns *atomic.Int64, stop func()) {
	t.Helper()
	var ln net.Listener
	var err error
	if denied {
		for p := 9100; p <= 9107; p++ {
			ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
			if err == nil {
				break
			}
		}
		if err != nil {
			t.Skipf("no denied port free on loopback: %v", err)
		}
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen control port: %v", err)
		}
	}
	conns = new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), conns, func() { _ = ln.Close() }
}

// A web service on an allowed port redirecting into a denied port must not
// pull httpx (or Chrome, when screenshots are on) into that port, while
// redirects themselves stay enabled.
func TestRunHttpx_RedirectIntoDeniedPortIsNotFollowed(t *testing.T) {
	deniedAddr, received, stop := listenCounting(t, true)
	defer stop()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/img" {
			_, _ = fmt.Fprintf(w, `<html><body><img src="http://%s/a.png"></body></html>`, deniedAddr)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("http://%s/", deniedAddr), http.StatusFound)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	t.Run("plain probe", func(t *testing.T) {
		received.Store(0)
		out := filepath.Join(t.TempDir(), "httpx.jsonl")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, _, err := RunHttpx(ctx, []string{ln.Addr().String()}, HttpxOptions{OutputFile: out, DisableStdout: true, Timeout: 2 * time.Second}); err != nil {
			t.Fatal(err)
		}
		if got := received.Load(); got != 0 {
			t.Fatalf("httpx followed a redirect into denied port %s (%d bytes)", deniedAddr, got)
		}
	})

	t.Run("screenshot", func(t *testing.T) {
		if os.Getenv("PD_AGENT_CHROME_TESTS") == "" {
			t.Skip("set PD_AGENT_CHROME_TESTS=1 to run the headless Chrome check")
		}
		received.Store(0)
		out := filepath.Join(t.TempDir(), "httpx.jsonl")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		urls := []string{"http://" + ln.Addr().String() + "/img", "http://" + ln.Addr().String() + "/redir"}
		if _, _, err := RunHttpx(ctx, urls, HttpxOptions{OutputFile: out, DisableStdout: true, Screenshot: true, StoreResponseDir: t.TempDir(), Timeout: 5 * time.Second}); err != nil {
			t.Fatal(err)
		}
		if got := received.Load(); got != 0 {
			t.Fatalf("headless chrome reached denied port %s (%d bytes)", deniedAddr, got)
		}
	})
}
