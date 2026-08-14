package cboxid

import (
	"net/url"
	"strings"
)

// ProfileURL is the URL of the instance's hosted account/profile page (self-service
// password, MFA, passkeys, sessions). A signed-in user is authenticated there by
// their Cbox ID session; returnTo, when non-empty, is passed so the page can link
// back to your app.
func (c *Client) ProfileURL(returnTo string) string {
	base := strings.TrimRight(c.cfg.Issuer, "/") + c.accountPath()
	if returnTo == "" {
		return base
	}
	return base + "?" + url.Values{"return_to": {returnTo}}.Encode()
}

// LogoutURL is the RP-initiated logout URL, or "" when the instance advertises none.
// returnTo, when non-empty, is where the OP sends the browser after signing out.
//
// THIS SIGNS OUT THIS BROWSER ONLY. Without an id_token_hint the OP cannot tell which
// End-User the request concerns — the endpoint is unauthenticated and reached by a
// redirect, so a request carrying no proof could otherwise be forged to end anyone's
// sessions everywhere. Cbox ID therefore ends only the calling browser's session when
// no hint is supplied. For "sign out everywhere", use LogoutURLWithHint and pass the
// user's id_token; see UPGRADING.md for laravel-id 1.8.0.
func (c *Client) LogoutURL(returnTo string) string {
	return c.LogoutURLWithHint(returnTo, "")
}

// LogoutURLWithHint is LogoutURL plus an id_token_hint — pass the user's id_token
// when you still hold it, and "" otherwise.
//
// THE HINT IS WHAT MAKES SIGN-OUT GLOBAL. Cbox ID revokes every session the person
// holds only when a hint it can verify names the subject holding the browser; without
// one it signs out this browser and leaves their other devices alone. That is a
// deliberate refusal rather than an omission — see the note on LogoutURL.
//
// Both forms always send client_id, even with an empty returnTo. The OP validates
// post_logout_redirect_uri against the registered allow-list of THAT client (OIDC
// RP-Initiated Logout 1.0 §2); a request that names no relying party gives it no
// list to check, so it drops the return URL and leaves the user on a bare "you are
// signed out" page. The hint is the spec's other way to identify the client, and
// additionally tells the OP whose session is ending.
func (c *Client) LogoutURLWithHint(returnTo, idTokenHint string) string {
	if c.endpoints.EndSession == "" {
		return ""
	}
	params := url.Values{"client_id": {c.cfg.ClientID}}
	if returnTo != "" {
		params.Set("post_logout_redirect_uri", returnTo)
	}
	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	return c.endpoints.EndSession + "?" + params.Encode()
}
