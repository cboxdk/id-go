package cboxid

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Prompt is an OIDC prompt value Cbox ID understands. The first four are OIDC Core
// §3.1.2.1; the last two are Cbox ID's organization steps.
type Prompt string

const (
	// PromptNone: no interaction at all; the callback carries an error if any is needed.
	PromptNone Prompt = "none"
	// PromptLogin: ask the person to sign in again even if Cbox ID has a session.
	PromptLogin Prompt = "login"
	// PromptConsent: show the consent screen even when consent was already given.
	PromptConsent Prompt = "consent"
	// PromptSelectAccount: let the person choose which account to continue as.
	PromptSelectAccount Prompt = "select_account"
	// PromptSelectOrganization: always show the hosted organization picker, even to
	// someone in a single organization.
	PromptSelectOrganization Prompt = "select_organization"
	// PromptCreateOrganization: the hosted "create a team" step — the person creates an
	// organization, becomes its owner, and the sign-in continues bound to it.
	PromptCreateOrganization Prompt = "create_organization"
)

// AuthParams optionally customizes a single authorization request.
type AuthParams struct {
	Scopes []string // overrides the configured default scopes
	// Prompt is one prompt value or several (sent space-separated). PromptNone cannot be
	// combined with anything else — OIDC Core §3.1.2.1 makes that an error at the
	// server, so it is refused here, where the error still points at your code.
	Prompt    []Prompt
	LoginHint string
	// Organization binds this sign-in to one organization (the organization parameter).
	// The person must hold an active membership in it; if they do not, the callback
	// carries error=access_denied and Authenticate returns an *OAuthError whose Code is
	// "access_denied". Empty means no binding.
	//
	// This is how an app switches organization: a new authorization bound to the other
	// one. See SwitchOrganization.
	Organization string
	// OrganizationHint preselects an organization in the hosted picker
	// (organization_hint) without binding to it — the person can still choose another.
	// Pair it with PromptSelectOrganization to always show the picker with your guess on
	// top. Empty means no hint.
	OrganizationHint string
}

// AuthorizationRequest is returned by CreateAuthorizationRequest. Persist State,
// CodeVerifier, Nonce and Organization (e.g. in the session) and hand them back to
// Authenticate in a Stored.
type AuthorizationRequest struct {
	URL          string
	State        string
	CodeVerifier string
	Nonce        string
	// Organization echoes AuthParams.Organization; empty when the request was not bound.
	// Persist it with the rest: Authenticate refuses tokens for any other organization.
	Organization string
}

// Callback holds the query parameters as they arrive on your callback route.
type Callback struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

// Stored holds the values you persisted from CreateAuthorizationRequest.
type Stored struct {
	State        string
	CodeVerifier string
	Nonce        string
	// Organization is the organization the sign-in was bound to (the request's
	// Organization), or empty.
	//
	// Checked, not trusted: a binding nobody verifies is a binding in name only. An
	// instance that predates the organization parameter ignores it and returns tokens
	// for whichever organization the session already had — and an app that switched to
	// "Globex" would then show Globex's name over Acme's data.
	Organization string
}

// CboxUser is the authenticated user. ID is the stable subject (sub) you key your
// local account on. Claims is the full verified id_token + userinfo claim set.
type CboxUser struct {
	ID    string
	Email string
	Name  string
	// OrganizationID is the active organization's id (org). Same as Organization.ID.
	OrganizationID string
	// Organization is the organization this session is bound to — id, name and the
	// person's membership tier in it (org, org_name, org_role) — or nil when none.
	Organization *ActiveOrganization
	// Roles are the app roles held in this session (roles); nil when there are none.
	Roles []string
	// Permissions are the permissions held in this session (permissions), already
	// expanded from Roles by Cbox ID; nil when there are none.
	Permissions []string
	// Actor is the staff member driving this session when it is a support session (the
	// RFC 8693 act claim); nil for an ordinary sign-in. See IsSupportSession.
	Actor *Actor
	// SessionID is the id_token's sid: the Cbox ID session this sign-in belongs to.
	// Store it to match an OIDC back-channel logout token, which names the session by
	// sid. Read from the signed id_token only, never from UserInfo; empty when absent.
	SessionID    string
	Claims       map[string]any
	AccessToken  string
	RefreshToken string
	IDToken      string
	Expiry       time.Time
	// Token is the raw oauth2 token, e.g. for building an authenticated client.
	Token *oauth2.Token
}

// CreateAuthorizationRequest begins login. Redirect the user to the returned URL and
// persist State, CodeVerifier, Nonce and Organization for Authenticate.
//
// It returns ErrConfiguration, before any redirect, when the request could only fail at
// the authorization server: the client has no RedirectURI (a client built for the device
// grant, see NewDeviceClient), PromptNone is combined with another prompt, or
// Organization is combined with PromptSelectOrganization or PromptCreateOrganization.
func (c *Client) CreateAuthorizationRequest(params AuthParams) (AuthorizationRequest, error) {
	if c.cfg.RedirectURI == "" {
		// Checked where it is needed rather than at construction, so a CLI can build a
		// client at all. An authorize URL without redirect_uri would fail at the
		// authorization server instead, describing a request the caller never knowingly
		// made.
		return AuthorizationRequest{}, fmt.Errorf("%w: RedirectURI is required for the authorization code flow — set it in Config, or use NewDeviceClient for a CLI", ErrConfiguration)
	}

	prompt, err := promptValue(params.Prompt)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if err := assertOrganizationParams(params, prompt); err != nil {
		return AuthorizationRequest{}, err
	}

	verifier := oauth2.GenerateVerifier()
	state := randToken()
	nonce := randToken()

	cfg := *c.oauth
	if len(params.Scopes) > 0 {
		cfg.Scopes = params.Scopes
	}

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	if len(prompt) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " ")))
	}
	if params.LoginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", params.LoginHint))
	}
	if params.Organization != "" {
		opts = append(opts, oauth2.SetAuthURLParam("organization", params.Organization))
	}
	if params.OrganizationHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("organization_hint", params.OrganizationHint))
	}

	return AuthorizationRequest{
		URL:          cfg.AuthCodeURL(state, opts...),
		State:        state,
		CodeVerifier: verifier,
		Nonce:        nonce,
		Organization: params.Organization,
	}, nil
}

// SwitchOrganization switches the signed-in person to another organization: a new
// authorization bound to organizationID. Persist and redirect exactly as for
// CreateAuthorizationRequest — it is one, with Organization set.
//
// Cbox ID already holds the person's session, so this is normally a redirect there and
// straight back with no sign-in form. The tokens that come back carry the new org,
// org_role, roles and permissions; replace your session with them rather than patching
// the old one, because every one of those can differ between organizations.
//
// A person who is not (or is no longer) an active member of that organization comes
// back with error=access_denied, which Authenticate returns as an *OAuthError whose Code
// is "access_denied" — answer it by staying in the current organization, not by signing
// the person out.
func (c *Client) SwitchOrganization(organizationID string, params AuthParams) (AuthorizationRequest, error) {
	if organizationID == "" {
		return AuthorizationRequest{}, fmt.Errorf("%w: SwitchOrganization needs the id of the organization to switch to", ErrConfiguration)
	}
	if params.Organization != "" || params.OrganizationHint != "" {
		return AuthorizationRequest{}, fmt.Errorf("%w: pass the organization to switch to as SwitchOrganization's first argument, not in AuthParams.Organization or AuthParams.OrganizationHint", ErrConfiguration)
	}

	params.Organization = organizationID
	return c.CreateAuthorizationRequest(params)
}

// promptValue flattens the prompt values into a de-duplicated list, refusing what the
// server would refuse. A value holding several space-separated prompts is split, so
// Prompt("none login") cannot slip past the PromptNone check.
func promptValue(prompt []Prompt) ([]string, error) {
	var values []string
	for _, p := range prompt {
		for _, value := range strings.Fields(string(p)) {
			if !slices.Contains(values, value) {
				values = append(values, value)
			}
		}
	}

	// OIDC Core §3.1.2.1: none with any other value is an error. Failing here names the
	// call that built it; failing at the server names nothing the caller can find.
	if slices.Contains(values, string(PromptNone)) && len(values) > 1 {
		return nil, fmt.Errorf("%w: PromptNone cannot be combined with another prompt value", ErrConfiguration)
	}

	return values, nil
}

// assertOrganizationParams refuses organization parameters that contradict the prompt.
// Each would reach the server as a request with two incompatible meanings and come back
// as a generic error after a full redirect — far from the line that built it.
//
// An empty Organization or OrganizationHint is Go's zero value and means "not set", so
// it is omitted from the URL rather than sent as a parameter that names nothing.
func assertOrganizationParams(params AuthParams, prompt []string) error {
	if params.Organization == "" {
		return nil
	}

	// Organization binds to an existing organization; both prompts below ask the person
	// to choose or create one. Sending both leaves the server to guess which you meant.
	if slices.Contains(prompt, string(PromptSelectOrganization)) {
		return fmt.Errorf("%w: AuthParams.Organization binds the sign-in to one organization, so PromptSelectOrganization has nothing to choose — use AuthParams.OrganizationHint to preselect an organization in the picker instead", ErrConfiguration)
	}
	if slices.Contains(prompt, string(PromptCreateOrganization)) {
		return fmt.Errorf("%w: AuthParams.Organization binds the sign-in to an existing organization and PromptCreateOrganization creates a new one — send one or the other", ErrConfiguration)
	}

	return nil
}

// Authenticate completes login on your callback route: it verifies the state,
// exchanges the code with the PKCE verifier, verifies the id_token, and returns the
// user. It returns ErrInvalidState on a state mismatch and wraps ErrAuthentication
// on any other failure. An error the authorization server sent to the callback
// (Callback.Error) is an *OAuthError carrying that code; a sign-in bound to an
// organization (Stored.Organization) is refused when the tokens are for another one.
func (c *Client) Authenticate(ctx context.Context, cb Callback, stored Stored) (*CboxUser, error) {
	if cb.State == "" || stored.State == "" ||
		subtle.ConstantTimeCompare([]byte(cb.State), []byte(stored.State)) != 1 {
		return nil, ErrInvalidState
	}
	if cb.Error != "" {
		// The code travels as a field, not only in the message: access_denied after a
		// SwitchOrganization means "not a member of that organization", which an app
		// answers by staying where it is — not by signing the person out.
		return nil, &OAuthError{Op: "authorization", Code: cb.Error, Description: cb.ErrorDescription}
	}
	if cb.Code == "" {
		return nil, fmt.Errorf("%w: the callback was missing an authorization code", ErrAuthentication)
	}

	ctx = withClient(ctx, c.cfg.HTTPClient)

	token, err := c.oauth.Exchange(ctx, cb.Code, oauth2.VerifierOption(stored.CodeVerifier))
	if err != nil {
		return nil, asOAuthError("token exchange", err)
	}

	user, err := c.userFromToken(ctx, token, stored.Nonce)
	if err != nil {
		return nil, err
	}

	if stored.Organization != "" && user.OrganizationID != stored.Organization {
		current := user.OrganizationID
		if current == "" {
			current = "no organization"
		}
		return nil, fmt.Errorf("%w: the sign-in was bound to organization %s, but the tokens are for %s. The instance may not support organization selection",
			ErrAuthentication, stored.Organization, current)
	}

	return user, nil
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
		Organization:   organizationFrom(claims),
		Roles:          stringList(claims["roles"]),
		Permissions:    stringList(claims["permissions"]),
		Actor:          actorFrom(claims["act"], 0),
		SessionID:      stringClaim(verified, "sid"),
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
