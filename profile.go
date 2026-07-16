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
func (c *Client) LogoutURL(returnTo string) string {
	if c.endpoints.EndSession == "" {
		return ""
	}
	if returnTo == "" {
		return c.endpoints.EndSession
	}
	return c.endpoints.EndSession + "?" + url.Values{"post_logout_redirect_uri": {returnTo}}.Encode()
}
