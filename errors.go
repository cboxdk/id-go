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
)
