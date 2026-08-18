package cboxid

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AuthParams optionally customizes a single authorization request.
type AuthParams struct {
	Scopes    []string // overrides the configured default scopes
	Prompt    string   // e.g. "login" or "consent"
	LoginHint string
}

// AuthorizationRequest is returned by CreateAuthorizationRequest. Persist State,
// CodeVerifier and Nonce (e.g. in the session) and hand them back to Authenticate.
type AuthorizationRequest struct {
	URL          string
	State        string
	CodeVerifier string
	Nonce        string
}

// Callback holds the query parameters as they arrive on your callback route.
type Callback struct {
	Code  string
	State string
	Error string
}

// Stored holds the values you persisted from CreateAuthorizationRequest.
type Stored struct {
	State        string
	CodeVerifier string
	Nonce        string
}

// CboxUser is the authenticated user. ID is the stable subject (sub) you key your
// local account on. Claims is the full verified id_token + userinfo claim set.
type CboxUser struct {
	ID             string
	Email          string
	Name           string
	OrganizationID string
	Claims         map[string]any
	AccessToken    string
	RefreshToken   string
	IDToken        string
	Expiry         time.Time
	// Token is the raw oauth2 token, e.g. for building an authenticated client.
	Token *oauth2.Token
}

// CreateAuthorizationRequest begins login. Redirect the user to the returned URL and
// persist State, CodeVerifier and Nonce for Authenticate.
func (c *Client) CreateAuthorizationRequest(params AuthParams) AuthorizationRequest {
	verifier := oauth2.GenerateVerifier()
	state := randToken()
	nonce := randToken()

	cfg := *c.oauth
	if len(params.Scopes) > 0 {
		cfg.Scopes = params.Scopes
	}

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	if params.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", params.Prompt))
	}
	if params.LoginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", params.LoginHint))
	}

	return AuthorizationRequest{
		URL:          cfg.AuthCodeURL(state, opts...),
		State:        state,
		CodeVerifier: verifier,
		Nonce:        nonce,
	}
}

// Authenticate completes login on your callback route: it verifies the state,
// exchanges the code with the PKCE verifier, verifies the id_token, and returns the
// user. It returns ErrInvalidState on a state mismatch and wraps ErrAuthentication
// on any other failure.
func (c *Client) Authenticate(ctx context.Context, cb Callback, stored Stored) (*CboxUser, error) {
	if cb.State == "" || stored.State == "" ||
		subtle.ConstantTimeCompare([]byte(cb.State), []byte(stored.State)) != 1 {
		return nil, ErrInvalidState
	}
	if cb.Error != "" {
		return nil, fmt.Errorf("%w: Cbox ID returned %q", ErrAuthentication, cb.Error)
	}
	if cb.Code == "" {
		return nil, fmt.Errorf("%w: the callback was missing an authorization code", ErrAuthentication)
	}

	ctx = withClient(ctx, c.cfg.HTTPClient)

	token, err := c.oauth.Exchange(ctx, cb.Code, oauth2.VerifierOption(stored.CodeVerifier))
	if err != nil {
		return nil, asOAuthError("token exchange", err)
	}

	return c.userFromToken(ctx, token, stored.Nonce)
}

// Refresh exchanges a refresh token for a fresh access token (OAuth 2.0
// refresh_token grant). Cbox ID rotates refresh tokens and detects reuse, so ALWAYS
// persist the returned token's RefreshToken and discard the one you passed in —
// presenting a rotated token again revokes the entire token family.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("%w: a refresh token is required", ErrAuthentication)
	}
	ctx = withClient(ctx, c.cfg.HTTPClient)
	token, err := c.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, asOAuthError("token refresh", err)
	}

	// VERIFIED BEFORE IT IS HANDED BACK. A caller that refreshes its session claims from
	// this token's id_token verified only the one it received at login; this one arrives
	// later, on a channel it never checks, and could be forged, expired, or for another
	// audience. The nonce is deliberately not re-checked — OIDC Core §12.2 says a
	// refreshed id_token need not carry one.
	if rawIDToken, ok := token.Extra("id_token").(string); ok && rawIDToken != "" {
		if _, err := c.verifier.Verify(ctx, rawIDToken); err != nil {
			return nil, fmt.Errorf("%w: the refreshed id_token failed verification: %v", ErrAuthentication, err)
		}
	}

	return token, nil
}

// userFromToken verifies a token's id_token (signature + issuer + audience, and the
// nonce when expectedNonce is non-empty), enriches it with userinfo, and builds a
// CboxUser. Shared by the authorization-code and device flows.
func (c *Client) userFromToken(ctx context.Context, token *oauth2.Token, expectedNonce string) (*CboxUser, error) {
	verified := map[string]any{}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken != "" {
		idToken, err := c.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return nil, fmt.Errorf("%w: id_token verification failed: %v", ErrAuthentication, err)
		}
		if expectedNonce != "" && idToken.Nonce != expectedNonce {
			return nil, fmt.Errorf("%w: id_token nonce did not match — possible replay", ErrAuthentication)
		}
		_ = idToken.Claims(&verified)
	}

	// Enrich with userinfo (email/name/org a minimal id_token may omit).
	profile := map[string]any{}
	if info, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		_ = info.Claims(&profile)
	}

	// OIDC Core §5.3.2: the UserInfo `sub` MUST match the id_token's, and when it does
	// not the response MUST NOT be used. UserInfo is fetched with a bearer token and its
	// body carries no signature of its own, so without this an IdP — or anything able to
	// answer as one — returns {"sub": "somebody-else"} and it becomes the identity.
	verifiedSub, hasVerified := verified["sub"].(string)
	profileSub, hasProfile := profile["sub"].(string)
	if hasVerified && hasProfile && subtle.ConstantTimeCompare([]byte(verifiedSub), []byte(profileSub)) != 1 {
		return nil, fmt.Errorf("%w: the UserInfo subject does not match the verified id_token", ErrAuthentication)
	}

	// ENRICHES, NEVER REPLACES. UserInfo fills in what a minimal id_token omits and the
	// verified claims go back on top, so the merge cannot move sub, iss, aud or anything
	// else the signature covered. Both maps used to be decoded into one, in that order,
	// which let the unsigned half win.
	claims := map[string]any{}
	for k, v := range profile {
		claims[k] = v
	}
	for k, v := range verified {
		claims[k] = v
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: the verified token carried no subject", ErrAuthentication)
	}

	return &CboxUser{
		ID:             sub,
		Email:          stringClaim(claims, "email"),
		Name:           stringClaim(claims, "name"),
		OrganizationID: stringClaim(claims, "org"),
		Claims:         claims,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		IDToken:        rawIDToken,
		Expiry:         token.Expiry,
		Token:          token,
	}, nil
}

func stringClaim(claims map[string]any, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}
	return ""
}

func randToken() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
