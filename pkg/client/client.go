package client

import (
	"crypto/tls"
	"net/http"
)

func CreateAuthenticatedClient(teamID, userId, pdcpApiKey string) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	// Create a custom RoundTripper to add headers to every request
	client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("X-Api-Key", pdcpApiKey)
		req.Header.Set("X-Team-Id", teamID)
		q := req.URL.Query()
		q.Add("user_id", userId)
		req.URL.RawQuery = q.Encode()
		return transport.RoundTrip(req)
	})

	return client, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rf roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rf(req)
}
