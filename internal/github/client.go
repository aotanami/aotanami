/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Client handles GitHub App JWT authentication and installation token management.
// It provides an authenticated *http.Client for GitHub API operations.
type Client struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	baseURL        string

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
	httpClient  *http.Client
	isPAT       bool
}

// NewClient creates a new GitHub App client from the given configuration.
func NewClient(appID, installationID int64, privateKeyPEM []byte, baseURL string) (*Client, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("github: failed to decode PEM block from private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format.
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("github: failed to parse private key: %w (also tried PKCS8: %v)", err, err2)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("github: PKCS8 key is not RSA")
		}
		key = rsaKey
	}

	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &Client{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		baseURL:        baseURL,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		isPAT:          false,
	}, nil
}

// NewPATClient creates a new GitHub client using a Personal Access Token (PAT).
func NewPATClient(token, baseURL string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &Client{
		accessToken: token,
		baseURL:     baseURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		isPAT:       true,
	}
}

// Token returns a valid installation access token or PAT.
func (c *Client) Token() (string, error) {
	if c.isPAT {
		return c.accessToken, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 5 min buffer).
	if c.accessToken != "" && time.Now().Add(5*time.Minute).Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	// Generate JWT.
	jwt, err := c.generateJWT()
	if err != nil {
		return "", fmt.Errorf("github: generating JWT: %w", err)
	}

	// Exchange JWT for installation token.
	token, expiry, err := c.createInstallationToken(jwt)
	if err != nil {
		return "", fmt.Errorf("github: creating installation token: %w", err)
	}

	c.accessToken = token
	c.tokenExpiry = expiry
	return c.accessToken, nil
}

// AuthenticatedClient returns an *http.Client that automatically sets
// the Authorization header with a valid installation token.
func (c *Client) AuthenticatedClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &tokenTransport{
			client: c,
			base:   http.DefaultTransport,
		},
	}
}

// BaseURL returns the GitHub API base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// generateJWT creates a GitHub App JWT (RS256) valid for 10 minutes.
func (c *Client) generateJWT() (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"iat": now.Add(-60 * time.Second).Unix(), // Issued 60s in the past for clock skew.
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": c.appID,
	}

	return signJWT(c.privateKey, claims)
}

// createInstallationToken exchanges a JWT for an installation access token.
func (c *Client) createInstallationToken(jwt string) (string, time.Time, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, c.installationID)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("requesting installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("installation token request returned %d", resp.StatusCode)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decoding token response: %w", err)
	}

	return result.Token, result.ExpiresAt, nil
}

// signJWT creates an RS256 JWT with the given claims. Implemented manually
// to avoid pulling in a JWT library dependency.
func signJWT(key *rsa.PrivateKey, claims map[string]interface{}) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	// Use crypto/rsa + crypto/sha256 for RS256.
	h := rsaSHA256Hash()
	h.Write([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(nil, key, rsaSHA256HashAlgo(), h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + sigB64, nil
}

// tokenTransport is an http.RoundTripper that adds the GitHub installation token.
type tokenTransport struct {
	client *Client
	base   http.RoundTripper
}

// RoundTrip adds the bearer token to requests.
func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.client.Token()
	if err != nil {
		return nil, fmt.Errorf("github: obtaining token: %w", err)
	}

	// Clone the request to avoid mutating the original.
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "token "+token)
	req2.Header.Set("Accept", "application/vnd.github+json")
	req2.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	return t.base.RoundTrip(req2)
}
