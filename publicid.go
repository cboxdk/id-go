package cboxid

import (
	"regexp"
	"strings"
)

// Cbox ID is moving its API, webhooks and console to prefixed public ids (org_01J9Z…,
// usr_01J9Z…: a type prefix and the object's ULID), while token claims (sub, org) keep
// the raw ULID. For a while both spellings arrive, often for the same object in the same
// flow, so compare ids with SameID rather than ==.
//
// Only <prefix>_<ULID> is unwrapped. Anything else (a test id such as org_1, a key) is
// compared exactly as given.
var publicIDPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,15}_([0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26})$`)

// RawID returns an id without its type prefix: the lowercase ULID for org_01J9Z…, the id
// itself for anything else. The raw form is the one token claims carry.
func RawID(id string) string {
	if match := publicIDPattern.FindStringSubmatch(id); match != nil {
		return strings.ToLower(match[1])
	}
	return id
}

// IsPublicID reports whether id is a prefixed public id (org_01J9Z…).
func IsPublicID(id string) bool {
	return publicIDPattern.MatchString(id)
}

// SameID reports whether two ids name the same object: org_01J9Z… and 01j9z… do. The
// empty string never matches anything.
func SameID(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	rawA, rawB := RawID(a), RawID(b)
	// Neither side a public id: they were already compared exactly.
	return (rawA != a || rawB != b) && strings.EqualFold(rawA, rawB)
}
