package cboxid

import "slices"

// OrganizationRole is the membership tier a person holds in the organization a token is
// bound to — the org_role claim. Coarse on purpose: it says who may administer the
// organization itself (invite, bill, delete). What they may do inside YOUR app is Roles
// and Permissions, which your app declares and Cbox ID assigns.
type OrganizationRole string

// The membership tiers Cbox ID issues, highest first.
const (
	OrganizationRoleOwner     OrganizationRole = "owner"
	OrganizationRoleAdmin     OrganizationRole = "admin"
	OrganizationRoleDeveloper OrganizationRole = "developer"
	OrganizationRoleMember    OrganizationRole = "member"
	OrganizationRoleViewer    OrganizationRole = "viewer"
)

// parseOrganizationRole reads an org_role claim value. Anything this SDK version does not
// know reads as "" — an unrecognised tier is never guessed upward into one that grants
// something.
func parseOrganizationRole(value any) OrganizationRole {
	role, _ := value.(string)
	switch OrganizationRole(role) {
	case OrganizationRoleOwner, OrganizationRoleAdmin, OrganizationRoleDeveloper,
		OrganizationRoleMember, OrganizationRoleViewer:
		return OrganizationRole(role)
	}
	return ""
}

// ActiveOrganization is the organization a token is bound to: the org, org_name and
// org_role claims.
type ActiveOrganization struct {
	// ID is the stable organization id (org).
	ID string
	// Name is its display name (org_name); empty when the instance sent none.
	Name string
	// Role is the person's membership tier in it (org_role). Empty when the claim is
	// absent, or carries a tier this SDK version does not know.
	Role OrganizationRole
}

// Actor is who is actually driving a delegated session — the RFC 8693 §4.1 act claim.
// Cbox ID sets it on the tokens of a SUPPORT SESSION: a staff member acting as one of
// your users, with a stated reason, for at most an hour, with no refresh token.
type Actor struct {
	// Subject is the actor's subject id (act.sub). Empty when an act claim is present but
	// not in the shape RFC 8693 describes: the session is still acted, and saying so
	// matters more than knowing by whom. See IsSupportSession.
	Subject string
	// Actor is the prior actor when delegation was chained (a nested act); nil otherwise.
	Actor *Actor
}

// ClaimSource is anything the claim helpers read from: the *CboxUser sign-in returned, or
// a claim set you verified yourself — an access token's payload on a resource server,
// say. A named map type (jwt.MapClaims) converts with map[string]any(claims).
type ClaimSource interface {
	*CboxUser | map[string]any
}

// OrganizationOf returns the organization the session is bound to, or nil when it is
// bound to none.
//
//	if org := cboxid.OrganizationOf(user); org != nil && org.Role == cboxid.OrganizationRoleOwner {
//		showBilling()
//	}
func OrganizationOf[S ClaimSource](source S) *ActiveOrganization {
	return organizationFrom(claimsOf(source))
}

// ActorOf returns the actor behind a support session (act), or nil for an ordinary
// session in which the person is acting as themselves.
func ActorOf[S ClaimSource](source S) *Actor {
	return actorFrom(claimsOf(source)["act"], 0)
}

// IsSupportSession reports whether somebody other than the signed-in person is driving
// this session — a staff member in a support session (the token carries act).
//
// FAIL-CLOSED. Any non-null act claim counts, including one whose shape this SDK cannot
// read: the check exists so an app can show a banner and refuse what a helper should
// never do on somebody's behalf (change their password, move their money), and a
// malformed claim is not evidence that nobody else is at the keyboard.
func IsSupportSession[S ClaimSource](source S) bool {
	return ActorOf(source) != nil
}

// RolesOf returns the app roles the session holds (the roles claim); nil when none.
func RolesOf[S ClaimSource](source S) []string {
	return stringList(claimsOf(source)["roles"])
}

// PermissionsOf returns the permissions the session holds (the permissions claim,
// already expanded from roles by Cbox ID); nil when none.
func PermissionsOf[S ClaimSource](source S) []string {
	return stringList(claimsOf(source)["permissions"])
}

// HasRole reports whether the session holds role. Exact match; no wildcards.
func HasRole[S ClaimSource](source S, role string) bool {
	return slices.Contains(RolesOf(source), role)
}

// HasPermission reports whether the session holds permission ("feature:action"). Exact
// match; no wildcards — a claim of "invoices:*" does not grant "invoices:delete", because
// nothing on the issuing side ever mints one.
func HasPermission[S ClaimSource](source S, permission string) bool {
	return slices.Contains(PermissionsOf(source), permission)
}

// IsSupportSession reports whether a staff member is driving this session. See the
// package-level IsSupportSession.
func (u *CboxUser) IsSupportSession() bool { return IsSupportSession(u) }

// HasRole reports whether the user holds role in this session. Exact match.
func (u *CboxUser) HasRole(role string) bool { return HasRole(u, role) }

// HasPermission reports whether the user holds permission in this session. Exact match.
func (u *CboxUser) HasPermission(permission string) bool { return HasPermission(u, permission) }

// claimsOf reads the claim set out of either kind of source. A *CboxUser is read from its
// verified Claims rather than its typed fields, so a hand-built user and one from
// Authenticate answer the same way.
func claimsOf[S ClaimSource](source S) map[string]any {
	switch s := any(source).(type) {
	case *CboxUser:
		if s == nil {
			return nil
		}
		return s.Claims
	case map[string]any:
		return s
	}
	return nil
}

func organizationFrom(claims map[string]any) *ActiveOrganization {
	id, _ := claims["org"].(string)
	if id == "" {
		return nil
	}
	name, _ := claims["org_name"].(string)
	return &ActiveOrganization{ID: id, Name: name, Role: parseOrganizationRole(claims["org_role"])}
}

// maxActorDepth bounds a nested act chain. RFC 8693 chains are a handful deep in
// practice, and one nested thousands deep is a bug or an attempt to exhaust the stack.
// Past the bound the chain is cut, not dropped — the session is still acted.
const maxActorDepth = 8

func actorFrom(claim any, depth int) *Actor {
	if claim == nil {
		return nil
	}

	record, ok := claim.(map[string]any)
	if !ok {
		// A string, a list, a number: not the RFC 8693 shape, but an act claim all the
		// same. Reporting "no actor" here is exactly the failure the check exists for.
		return &Actor{}
	}

	sub, _ := record["sub"].(string)
	actor := &Actor{Subject: sub}
	if depth+1 < maxActorDepth {
		actor.Actor = actorFrom(record["act"], depth+1)
	}
	return actor
}

func stringList(claim any) []string {
	var out []string
	switch values := claim.(type) {
	case []any:
		for _, value := range values {
			if s, ok := value.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, s := range values {
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
