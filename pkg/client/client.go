package client

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
)

func CreateAuthenticatedClient(teamID, pdcpApiKey string) (*http.Client, error) {
	transport := &http.Transport{
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
