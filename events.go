package cboxid

import "strings"

// Cbox ID is adding its product key to every webhook event type:
// organization.member_added becomes id.organization.member_added, and user.login becomes
// id.user.signed_in (a past verb). For a while a delivery may carry either name, so
// match event types with SameEventType rather than ==.

// EventTypePrefix is the product key Cbox ID puts in front of its event types.
const EventTypePrefix = "id."

// renamedEventTypes are the old names whose new name is not just the prefix added.
var renamedEventTypes = map[string]string{
	"user.login": "id.user.signed_in",
}

// CurrentEventType returns the id.* name of an event type, whichever name it was given
// in: organization.member_added → id.organization.member_added, user.login →
// id.user.signed_in. The wildcard "*" and the empty string come back unchanged.
func CurrentEventType(eventType string) string {
	if eventType == "" || eventType == "*" || strings.HasPrefix(eventType, EventTypePrefix) {
		return eventType
	}
	if renamed, ok := renamedEventTypes[eventType]; ok {
		return renamed
	}
	return EventTypePrefix + eventType
}

// LegacyEventType returns the name an event type had before the id.* names, whichever
// name it was given in: id.user.signed_in → user.login.
func LegacyEventType(eventType string) string {
	if !strings.HasPrefix(eventType, EventTypePrefix) {
		return eventType
	}
	for old, renamed := range renamedEventTypes {
		if renamed == eventType {
			return old
		}
	}
	return strings.TrimPrefix(eventType, EventTypePrefix)
}

// SameEventType reports whether two event type names are the same event:
// user.login and id.user.signed_in are; organization.member_added and
// id.organization.member_added are.
func SameEventType(a, b string) bool {
	return a == b || (a != "" && b != "" && LegacyEventType(a) == LegacyEventType(b))
}
