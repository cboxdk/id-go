package cboxid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The browser-facing half of Cbox ID, read from Go.
//
// Everything else in this package assumes a confidential client: it holds a secret, it
// exchanges codes, it verifies webhooks. A PUBLISHABLE key is the opposite — public on
// purpose, safe in a bundle, and useful only from the origins its owner registered.
//
// Why a Go client for a browser-facing API at all: a server-rendered page still has to
// know what to draw. Reading the environment's sign-in configuration here — the
// endpoints, the social buttons, the customer's theme — lets a Go template render a
// themed sign-in box without shipping a JavaScript SDK to do it.

// ErrNotPublishableKey is returned when something that is not a pk_ key is supplied.
//
// Caught at construction rather than at the first request: putting a client secret where
// a public key belongs is the exact mistake this channel exists to make unnecessary, and
// as an opaque 401 in a log the cause is invisible.
var ErrNotPublishableKey = errors.New("cboxid: publishable key must start with pk_test_ or pk_live_; client secrets must never be used here")

// FrontendConfig is everything needed to draw a sign-in box, and nothing that identifies
// anybody.
type FrontendConfig struct {
	Mode       string            `json:"mode"`
	Issuer     string            `json:"issuer"`
	Endpoints  map[string]string `json:"endpoints"`
	Social     []SocialProvider  `json:"social"`
	Appearance map[string]any    `json:"appearance,omitempty"`
}

// SocialProvider is a button to draw — a label and a provider key, never an internal id.
type SocialProvider struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
}

// FrontendSession is who is signed in, or nobody.
type FrontendSession struct {
	User *FrontendUser `json:"user"`
}

// FrontendUser is the little a component needs: a label, an initial, an id.
type FrontendUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// FrontendClient reads the public configuration and the current session.
type FrontendClient struct {
	issuer string
	key    string
	http   *http.Client

	once   sync.Once
	config *FrontendConfig
	err    error
}

// NewFrontendClient builds a client for the public channel.
func NewFrontendClient(issuer, publishableKey string, httpClient *http.Client) (*FrontendClient, error) {
	if issuer == "" {
		return nil, errors.New("cboxid: issuer is required")
	}

	if !strings.HasPrefix(publishableKey, "pk_") {
		return nil, ErrNotPublishableKey
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &FrontendClient{
		issuer: strings.TrimRight(issuer, "/"),
		key:    publishableKey,
		http:   httpClient,
	}, nil
}

// IsLive reports whether this key drives real sign-ins — handy for a "test mode" badge.
func (c *FrontendClient) IsLive() bool {
	return strings.HasPrefix(c.key, "pk_live_")
}

// Config returns the public sign-in configuration.
//
// Fetched once per client. The document is small and changes when somebody edits it in
// the console, so a long-lived process picks changes up when it next builds a client
// rather than mid-request — the right trade for something that decides layout.
func (c *FrontendClient) Config(ctx context.Context) (*FrontendConfig, error) {
	c.once.Do(func() {
		var config FrontendConfig

		if err := c.get(ctx, "/frontend/v1/config", "", &config); err != nil {
			c.err = err

			return
		}

		c.config = &config
	})

	return c.config, c.err
}

// Session returns who is signed in, given a token the caller already holds.
//
// An empty token yields an empty session rather than an error: signed-out is a state, and
// code that renders an avatar on every page should not have to treat a rejection as one.
// The publishable key grants nothing here — the token is the entire authority.
func (c *FrontendClient) Session(ctx context.Context, accessToken string) (*FrontendSession, error) {
	if accessToken == "" {
		return &FrontendSession{}, nil
	}

	var session FrontendSession

	if err := c.get(ctx, "/frontend/v1/session", accessToken, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (c *FrontendClient) get(ctx context.Context, path, bearer string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+path, nil)
	if err != nil {
		return err
	}

	// A header, never a query string: a query string puts the key in server logs, in
	// Referer on every outbound link, and in browser history.
	request.Header.Set("X-Cbox-Publishable-Key", c.key)
	request.Header.Set("Accept", "application/json")

	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("cboxid: Cbox ID refused the request (%d); check that this caller's origin is on the key's allow-list and that the key is not revoked", response.StatusCode)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("cboxid: Cbox ID returned %d", response.StatusCode)
	}

	return json.NewDecoder(response.Body).Decode(into)
}
