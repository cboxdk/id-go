// Package cboxid is a turnkey Cbox ID client for Go. It speaks standard OpenID
// Connect against a Cbox ID instance — so integrating is a redirect and a callback,
// not a rewrite — and adds the conveniences a hosted-identity product needs: a
// redirect to the instance's hosted profile page, and back-channel helpers (machine
// tokens, userinfo, RFC 7662 introspection, RFC 7009 revocation, webhook
// verification).
//
// Login is hardened by default: PKCE (S256), a CSRF state check, a nonce, and full
// id_token signature + issuer + audience verification against the instance's JWKS.
// The heavy lifting is delegated to the vetted github.com/coreos/go-oidc/v3 and
// golang.org/x/oauth2 — no hand-rolled crypto or JWT parsing.
package cboxid

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config configures a Client.
type Config struct {
	// Issuer is the base URL of the Cbox ID instance, e.g. https://id.acme.com.
	Issuer string
	// ClientID is your registered OAuth client id.
	ClientID string
	// ClientSecret is required for confidential apps, machine tokens, introspection
	// and revocation. Leave empty for public clients doing only PKCE login.
	ClientSecret string
	// RedirectURI is your callback URL, registered on the client.
	RedirectURI string
	// Scopes requested at login. Defaults to openid, profile, email.
	Scopes []string
	// AccountPath is the instance's hosted account page. Defaults to /settings.
	AccountPath string
	// HTTPClient, when set, is used for all back-channel calls (else http.DefaultClient).
	HTTPClient *http.Client
	// Permissions and Roles declare this app's authorization catalog in code, for
	// PublishManifest to push to Cbox ID on deploy. Cbox ID owns identity and who
	// holds what; the app owns what a role means. Leave empty if you don't publish a
	// manifest. Requires the client to hold the apps.manifest scope.
	Permissions []Permission
	Roles       []Role
}

// NewDeviceClient builds a Client for the device authorization grant (RFC 8628) — a
// CLI, a CI job, a container, a TV: anything with no browser of its own.
//
// A separate constructor because the configuration genuinely differs rather than
// overlaps. There is no redirect URI, and there is no client secret: a binary on
// somebody's laptop cannot keep one, so a device client is registered public and holds
// none. Naming those absences in a type is clearer than documenting them as fields to
// leave empty.
func NewDeviceClient(ctx context.Context, cfg DeviceConfig) (*Client, error) {
	return New(ctx, Config{
		Issuer:      cfg.Issuer,
		ClientID:    cfg.ClientID,
		Scopes:      cfg.Scopes,
		HTTPClient:  cfg.HTTPClient,
		AccountPath: cfg.AccountPath,
	})
}

// DeviceConfig is the configuration a device-grant client actually has.
type DeviceConfig struct {
	// Issuer is the base URL of the Cbox ID instance, e.g. https://id.acme.com.
	Issuer string
	// ClientID is your registered OAuth client id. Register the app as "CLI or device"
	// in the console and this is all it hands you — there is nothing to keep secret.
	ClientID string
	// Scopes requested at login. Defaults to openid, profile, email.
	//
	// These must be within what the app is REGISTERED for: a device request naming a
	// scope outside that ceiling is refused with invalid_scope rather than quietly
	// reduced, because no browser is in front of it to notice a smaller grant. Include
	// offline_access if you want the session to outlive the first hour.
	Scopes []string
	// AccountPath is the instance's hosted account page. Defaults to /settings.
	AccountPath string
	// HTTPClient, when set, is used for all back-channel calls (else http.DefaultClient).
	HTTPClient *http.Client
}

// Client is a Cbox ID client. Construct it with New and share it; it is safe for
// concurrent use.
type Client struct {
	cfg       Config
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	oauth     *oauth2.Config
	endpoints endpoints
}

type endpoints struct {
	Introspection       string `json:"introspection_endpoint"`
	Revocation          string `json:"revocation_endpoint"`
	EndSession          string `json:"end_session_endpoint"`
	DeviceAuthorization string `json:"device_authorization_endpoint"`
}

// New builds a Client, discovering the instance's endpoints and JWKS from
// {issuer}/.well-known/openid-configuration.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("%w: Issuer is required", ErrConfiguration)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("%w: ClientID is required", ErrConfiguration)
	}
	// NOT REQUIRED HERE. It is required by the flow that uses it, and the device grant
	// does not: a CLI has no callback URL, which is the entire reason RFC 8628 exists.
	// Demanding one at construction meant every CLI wrote
	// `RedirectURI: "http://localhost", // unused` — a value that means nothing, sitting
	// where a security-relevant one usually is, in the file the next person copies from.
	// {@see NewDeviceClient}, and the check in CreateAuthorizationRequest.
	if err := assertSecureIssuer(cfg.Issuer); err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(withClient(ctx, cfg.HTTPClient), strings.TrimRight(cfg.Issuer, "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: discovery failed: %v", ErrAuthentication, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	client := &Client{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
	}
	// Optional endpoints not surfaced by go-oidc's Endpoint().
	_ = provider.Claims(&client.endpoints)
	client.oauth.Endpoint.DeviceAuthURL = client.endpoints.DeviceAuthorization
	return client, nil
}

func (c *Client) accountPath() string {
	path := c.cfg.AccountPath
	if path == "" {
		// "/account", not "/settings": the latter is the organization-admin page, which
		// redirects a non-admin to "/account" and drops return_to on the way.
		return "/account"
	}
	return "/" + strings.TrimLeft(path, "/")
}

// withClient injects a custom *http.Client into the context for go-oidc / oauth2.
func withClient(ctx context.Context, httpClient *http.Client) context.Context {
	if httpClient != nil {
		return oidc.ClientContext(ctx, httpClient)
	}
	return ctx
}

// assertSecureIssuer refuses an issuer that is not HTTPS.
//
// Every request this SDK makes to the issuer carries a credential: the authorization
// code, the PKCE verifier, the client secret, the refresh token. Over http a network
// attacker reads all of them — and replaces the discovery document and the JWKS, after
// which a forged id_token verifies cleanly and the verification below proves nothing.
//
// Loopback stays allowed: a native app's own callback listener is loopback by
// definition (RFC 8252), and a development instance runs there.
func assertSecureIssuer(issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: Issuer is not a valid URL: %v", ErrConfiguration, err)
	}

	if parsed.Scheme == "https" {
		return nil
	}

	if parsed.Scheme == "http" {
		switch parsed.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}

	return fmt.Errorf("%w: Issuer must be https (got %s)", ErrConfiguration, issuer)
}
