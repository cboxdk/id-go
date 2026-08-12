package cboxid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
var ErrNotPublishableKey = fmt.Errorf("%w: publishable key must start with pk_test_ or pk_live_; client secrets must never be used here", ErrConfiguration)

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

	mu     sync.Mutex
	config *FrontendConfig
}

// NewFrontendClient builds a client for the public channel.
func NewFrontendClient(issuer, publishableKey string, httpClient *http.Client) (*FrontendClient, error) {
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrConfiguration)
	}

	if !strings.HasPrefix(publishableKey, "pk_") {
		return nil, ErrNotPublishableKey
	}

	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
			// NO REDIRECTS. Every request this client makes carries the publishable key in
			// a custom header, and `session` carries a bearer token — Go strips
			// `Authorization` across domains but never across ports, and never strips a
			// custom header at all. A misconfigured issuer that 302s to somebody else's
			// host would hand both to them. There is nothing legitimate at the other end
			// of a redirect here: the issuer is a URL an operator configured.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
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
// Fetched once per client, and CACHED ONLY ON SUCCESS. It used to be a sync.Once, which
// caches the failure too: one network blip — or a first caller whose context was already
// cancelled — poisoned the client for the lifetime of the process, and a server that draws
// a sign-in box on every page never drew one again until it was restarted. A mutex costs
// an uncontended lock per call and cannot do that.
//
// The document is small and changes when somebody edits it in the console, so a long-lived
// process picks changes up when it next builds a client rather than mid-request — the
// right trade for something that decides layout.
func (c *FrontendClient) Config(ctx context.Context) (*FrontendConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.config != nil {
		return c.config, nil
	}

	var config FrontendConfig

	if err := c.get(ctx, "/frontend/v1/config", "", &config); err != nil {
		return nil, err
	}

	c.config = &config

	return c.config, nil
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
		// Wrapped, not returned raw: a caller who gets `dial tcp: …` back goes to the
		// logs, and this channel's most common failure — an origin that is not on the
		// key's allow-list — reaches a caller as a transport error BY DESIGN, because the
		// refusal carries no CORS headers. Saying so is the difference between an
		// afternoon and a minute.
		return fmt.Errorf("%w: could not reach Cbox ID at %s: %w", ErrTransport, c.issuer, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		// THE SERVER'S OWN REASON FIRST, and wrapped in this package's sentinel so a
		// caller can errors.Is an origin refusal apart from an outage. It answers
		// precisely — "No publishable key was presented" is not the same problem as "That
		// publishable key cannot be used from this origin" — and substituting a guess for
		// it made this client less precise than the API it wraps.
		return fmt.Errorf("%w: %s", ErrUnauthorized, described(response,
			fmt.Sprintf("Cbox ID refused the request (%d); check that this caller's origin is on the key's allow-list and that the key is not revoked", response.StatusCode)))
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%w: %s", ErrServer, described(response,
			fmt.Sprintf("Cbox ID returned %d", response.StatusCode)))
	}

	if err := json.NewDecoder(response.Body).Decode(into); err != nil {
		return fmt.Errorf("%w: Cbox ID returned a body that is not the expected JSON document: %w", ErrServer, err)
	}

	return nil
}

// described returns the server's own error_description, or the fallback.
func described(response *http.Response, fallback string) string {
	var body struct {
		Description string `json:"error_description"`
	}

	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body); err != nil || body.Description == "" {
		return fallback
	}

	return body.Description
}
