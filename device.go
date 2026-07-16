package cboxid

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

// DeviceAuth is a pending device authorization (RFC 8628). Show UserCode to the
// person and send them to VerificationURI (or VerificationURIComplete, which
// embeds the code), then call PollDeviceToken.
type DeviceAuth struct {
	// DeviceCode is the secret your CLI polls with; don't show it to the user.
	DeviceCode string
	// UserCode is the short code the user types on the verification page.
	UserCode string
	// VerificationURI is where the user goes to authorize.
	VerificationURI string
	// VerificationURIComplete embeds the user code, for a clickable link / QR.
	VerificationURIComplete string
	// Expiry is when this authorization stops being valid.
	Expiry time.Time
	// Interval is the minimum seconds between polls.
	Interval int64

	response *oauth2.DeviceAuthResponse
}

// RequestDeviceAuthorization starts the device authorization grant — the flow a CLI
// or a TV app uses: the user authorizes on a second device (phone/laptop) while your
// program polls. Requires the instance to support the device grant.
func (c *Client) RequestDeviceAuthorization(ctx context.Context, params DeviceParams) (*DeviceAuth, error) {
	cfg := *c.oauth
	if len(params.Scopes) > 0 {
		cfg.Scopes = params.Scopes
	}

	response, err := cfg.DeviceAuth(withClient(ctx, c.cfg.HTTPClient))
	if err != nil {
		return nil, fmt.Errorf("%w: device authorization request failed: %v", ErrAuthentication, err)
	}

	return &DeviceAuth{
		DeviceCode:              response.DeviceCode,
		UserCode:                response.UserCode,
		VerificationURI:         response.VerificationURI,
		VerificationURIComplete: response.VerificationURIComplete,
		Expiry:                  response.Expiry,
		Interval:                response.Interval,
		response:                response,
	}, nil
}

// DeviceParams optionally scopes a device authorization.
type DeviceParams struct {
	Scopes []string
}

// PollDeviceToken blocks until the user approves the DeviceAuth (or it expires),
// honoring the poll interval and the authorization_pending / slow_down signals, then
// verifies the id_token and returns the user. Pass a context with a deadline to bound
// the wait. There is no nonce in the device flow, so the nonce check is skipped;
// signature, issuer and audience are still verified.
func (c *Client) PollDeviceToken(ctx context.Context, auth *DeviceAuth) (*CboxUser, error) {
	if auth == nil || auth.response == nil {
		return nil, fmt.Errorf("%w: PollDeviceToken needs a DeviceAuth from RequestDeviceAuthorization", ErrConfiguration)
	}

	ctx = withClient(ctx, c.cfg.HTTPClient)
	token, err := c.oauth.DeviceAccessToken(ctx, auth.response)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: device token exchange failed: %v", ErrAuthentication, err)
	}

	return c.userFromToken(ctx, token, "")
}
