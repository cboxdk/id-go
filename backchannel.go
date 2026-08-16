package cboxid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// MachineTokenParams optionally scopes a machine token.
type MachineTokenParams struct {
	Scopes   []string
	Resource string // RFC 8707 resource indicator
}

// MachineToken returns a machine (client-credentials) access token for calling Cbox
// ID APIs as your app, not on a user's behalf. Requires a client secret.
func (c *Client) MachineToken(ctx context.Context, params MachineTokenParams) (string, error) {
	if c.cfg.ClientSecret == "" {
		return "", fmt.Errorf("%w: MachineToken requires a ClientSecret", ErrConfiguration)
	}
	cc := clientcredentials.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		TokenURL:     c.oauth.Endpoint.TokenURL,
		Scopes:       params.Scopes,
	}
	if params.Resource != "" {
		cc.EndpointParams = url.Values{"resource": {params.Resource}}
	}
	token, err := cc.Token(withClient(ctx, c.cfg.HTTPClient))
	if err != nil {
		return "", fmt.Errorf("%w: machine token request failed: %v", ErrAuthentication, err)
	}
	return token.AccessToken, nil
}

// UserInfo returns the OIDC userinfo claims for an access token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	info, err := c.provider.UserInfo(
		withClient(ctx, c.cfg.HTTPClient),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken}),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo request failed: %v", ErrAuthentication, err)
	}
	claims := map[string]any{}
	if err := info.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: userinfo could not be parsed: %v", ErrAuthentication, err)
	}
	return claims, nil
}

// Introspect performs RFC 7662 token introspection (confidential-client auth). The
// returned map's "active" field tells you if the token is currently valid.
func (c *Client) Introspect(ctx context.Context, token string) (map[string]any, error) {
	if c.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: Introspect requires a ClientSecret", ErrConfiguration)
	}
	if c.endpoints.Introspection == "" {
		return nil, fmt.Errorf("%w: the instance does not advertise an introspection_endpoint", ErrConfiguration)
	}

	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoints.Introspection,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)

	httpClient := c.cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: introspection request failed: %v", ErrAuthentication, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: introspection returned status %d", ErrAuthentication, resp.StatusCode)
	}

	result := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("%w: introspection response could not be parsed: %v", ErrAuthentication, err)
	}
	return result, nil
}

// Token type hints for Revoke (RFC 7009). The hint only tells the server which store
// to search first; it must still find the token if the hint is wrong or absent.
const (
	HintAccessToken  = "access_token"
	HintRefreshToken = "refresh_token"
)

// Revoke performs RFC 7009 token revocation. Revoking a refresh token also drops the
// whole token family, so this is what a real "sign out everywhere" does.
//
// PUBLIC CLIENTS TOO. This refused without a ClientSecret, so the clients that most need
// it could not call it: a PKCE native or CLI app authenticates with "none", holds no
// secret, and is exactly the case where a refresh token sits on a device somebody has
// just signed out of. Cbox ID's revocation endpoint accepts a public client and
// advertises "none" among its revocation auth methods; RFC 7009 §2.1 scopes each
// revocation to the calling client, so the only capability is destroying a token you are
// already holding. A confidential client still sends Basic; a public one names itself in
// the body.
//
// Per RFC 7009 the server answers 200 for an unknown or already-revoked token, so a
// nil error means "the token is not valid any more", not "it existed". Pass
// HintAccessToken or HintRefreshToken as tokenTypeHint, or "" for none.
func (c *Client) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	if c.endpoints.Revocation == "" {
		return fmt.Errorf("%w: the instance does not advertise a revocation_endpoint", ErrConfiguration)
	}

	form := url.Values{"token": {token}, "client_id": {c.cfg.ClientID}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoints.Revocation,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	}

	httpClient := c.cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: revocation request failed: %v", ErrAuthentication, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%w: revocation returned status %d", ErrAuthentication, resp.StatusCode)
	}
	return nil
}
