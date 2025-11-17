package client

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func CreateAuthenticatedClient(teamID, pdcpApiKey string) (*http.Client, error) {
	// Create a dialer with timeout and keepalive settings
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
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
		Timeout:   60 * time.Second, // Overall request timeout
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
