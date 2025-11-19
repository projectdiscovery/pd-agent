package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func CreateAuthenticatedClient(teamID, pdcpApiKey string) (*http.Client, error) {
	// Create a custom dialer that forces IPv4 only
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
		// Custom dial function that forces IPv4 only
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Force IPv4 by changing network type
			if network == "tcp" {
				network = "tcp4"
			}
			return dialer.DialContext(ctx, network, addr)
		},
		// Connection management settings to prevent socket issues
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   10,
		// Add response header timeout to prevent hanging connections
		ResponseHeaderTimeout: 30 * time.Second,
	}

	proxyURL := os.Getenv("PROXY_URL")
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Transport: transport,
		// Add overall request timeout to prevent hanging requests
		Timeout: 60 * time.Second,
	}

	// Create a custom RoundTripper to add headers to every request
	client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("X-Api-Key", pdcpApiKey)
		req.Header.Set("X-Team-Id", teamID)
		return transport.RoundTrip(req)
	})

	return client, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rf roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rf(req)
}
