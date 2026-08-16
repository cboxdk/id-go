package cboxid

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

var (
	// ErrConfiguration indicates a missing or invalid configuration value.
	ErrConfiguration = errors.New("cboxid: configuration error")
	// ErrInvalidState indicates the login state did not match — a forged or stale
	// callback. Treat it as a fresh start, not an error to show the user.
	ErrInvalidState = errors.New("cboxid: login state did not match")
	// ErrAuthentication indicates login could not be completed, or a token failed
	// verification.
	ErrAuthentication = errors.New("cboxid: authentication failed")
	// ErrManifestRejected indicates Cbox ID refused an authorization-manifest push —
	// e.g. the client lacks the apps.manifest scope, or the manifest was malformed.
	// The wrapped message carries the HTTP status and the server's response body.
	ErrManifestRejected = errors.New("cboxid: manifest push rejected")
	// ErrUnauthorized indicates the Frontend API refused this caller: the publishable
	// key is unknown or revoked, or the calling origin is not on its allow-list. A
	// sentinel of its own because it is the one failure a caller can DO something about,
	// and telling it apart from an outage is the whole point of having a taxonomy.
	ErrUnauthorized = errors.New("cboxid: refused by the Frontend API")
	// ErrTransport indicates Cbox ID could not be reached at all.
	ErrTransport = errors.New("cboxid: could not reach Cbox ID")
	// ErrServer indicates Cbox ID answered, with something unusable.
	ErrServer = errors.New("cboxid: unusable response from Cbox ID")
)

// OAuthError is a token-endpoint failure with the server's own answer preserved.
//
// It wraps ErrAuthentication, so every existing errors.Is(err, ErrAuthentication) check
// keeps working; what it adds is the detail those checks could not reach. The
// golang.org/x/oauth2 library already parses the RFC 6749 §5.2 body into a
// *oauth2.RetrieveError, and this package was flattening all of it into %v — so a caller
// had one prose string for outcomes that demand opposite responses. invalid_grant on a
// refresh means the session is over and the person must sign in again; a 429 means the
// same request succeeds unchanged if you wait, and the server says how long.
type OAuthError struct {
	// Op is what was being attempted, e.g. "token refresh".
	Op string
	// Code is the RFC 6749 §5.2 error code, empty when the server sent none.
	Code string
	// Description is the server's error_description, verbatim. Not end-user copy.
	Description string
	// Status is the HTTP status, for the cases where the body says nothing useful.
	Status int
	// RetryAfter is seconds off the Retry-After header, 0 when absent or not an
	// integer. The HTTP-date form is legal per RFC 9110 and deliberately not parsed:
	// guessing at clock skew is worse than saying nothing, and RateLimited() still
	// tells the caller to back off.
	RetryAfter int
}

func (e *OAuthError) Error() string {
	detail := e.Code
	if detail == "" {
		detail = fmt.Sprintf("HTTP %d", e.Status)
	}

	return fmt.Sprintf("%s: %s: %s", ErrAuthentication, e.Op, detail)
}

// Unwrap keeps errors.Is(err, ErrAuthentication) true.
func (e *OAuthError) Unwrap() error { return ErrAuthentication }

// RateLimited reports whether waiting RetryAfter seconds and repeating the same request
// unchanged is worth it. It is the one back-channel failure where it is.
func (e *OAuthError) RateLimited() bool { return e.Status == http.StatusTooManyRequests }

// asOAuthError converts an x/oauth2 failure into an OAuthError, keeping whatever the
// server said. Any other error is wrapped unchanged — inventing a code would make
// errors.As succeed on a transport failure that never reached the server.
func asOAuthError(op string, err error) error {
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) {
		return fmt.Errorf("%w: %s: %v", ErrAuthentication, op, err)
	}

	out := &OAuthError{
		Op:          op,
		Code:        retrieve.ErrorCode,
		Description: retrieve.ErrorDescription,
	}

	if retrieve.Response != nil {
		out.Status = retrieve.Response.StatusCode

		if seconds, convErr := strconv.Atoi(strings.TrimSpace(retrieve.Response.Header.Get("Retry-After"))); convErr == nil && seconds >= 0 {
			out.RetryAfter = seconds
		}
	}

	return out
}
