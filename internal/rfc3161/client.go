package rfc3161

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// maxResponseSize caps how much of a TSA answer is read (tokens are a few KB).
const maxResponseSize = 1 << 20

// Client requests timestamps from a single TSA endpoint.
type Client struct {
	URL        string
	HTTPClient *http.Client
}

// NewClient returns a Client for the given TSA URL with a sane HTTP timeout.
func NewClient(url string) *Client {
	return &Client{
		URL:        url,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Request obtains an RFC 3161 timestamp token attesting the given SHA-256
// digest. A fresh random nonce ties the answer to this request. It returns
// the raw DER token, suitable for saving to disk, and its parsed summary.
func (c *Client) Request(digest []byte) ([]byte, *TokenInfo, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, fmt.Errorf("rfc3161: failed to generate nonce: %w", err)
	}

	reqDER, err := newRequest(digest, nonce)
	if err != nil {
		return nil, nil, err
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	resp, err := httpClient.Post(c.URL, "application/timestamp-query", bytes.NewReader(reqDER))
	if err != nil {
		return nil, nil, fmt.Errorf("rfc3161: TSA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("rfc3161: TSA returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, nil, fmt.Errorf("rfc3161: failed to read TSA response: %w", err)
	}

	return parseResponse(body, digest, nonce)
}
