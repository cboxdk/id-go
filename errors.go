package cboxid

import "errors"

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
)
