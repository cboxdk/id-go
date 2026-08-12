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
