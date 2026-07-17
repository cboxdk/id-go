// Package cboxid is a turnkey Cbox ID client for Go. It speaks standard OpenID
// Connect against a Cbox ID instance — so integrating is a redirect and a callback,
// not a rewrite — and adds the conveniences a hosted-identity product needs: a
// redirect to the instance's hosted profile page, and back-channel helpers (machine
// tokens, userinfo, RFC 7662 introspection, webhook verification).
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
	// ClientSecret is required for confidential apps, machine tokens and
	// introspection. Leave empty for public clients doing only PKCE login.
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
	if cfg.RedirectURI == "" {
		return nil, fmt.Errorf("%w: RedirectURI is required", ErrConfiguration)
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
		return "/settings"
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
