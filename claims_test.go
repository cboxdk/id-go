package cboxid_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

// claimsJSON decodes a claim set the way a verified JWT payload arrives: objects as
// map[string]any, arrays as []any.
func claimsJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return claims
}

func TestOrganizationOf(t *testing.T) {
	claims := claimsJSON(t, `{"org":"org_1","org_name":"Acme","org_role":"admin"}`)

	org := cboxid.OrganizationOf(claims)
	if org == nil || org.ID != "org_1" || org.Name != "Acme" || org.Role != cboxid.OrganizationRoleAdmin {
		t.Fatalf("OrganizationOf = %+v", org)
	}

	for _, role := range []cboxid.OrganizationRole{
		cboxid.OrganizationRoleOwner, cboxid.OrganizationRoleAdmin, cboxid.OrganizationRoleDeveloper,
		cboxid.OrganizationRoleMember, cboxid.OrganizationRoleViewer,
	} {
		got := cboxid.OrganizationOf(map[string]any{"org": "org_1", "org_role": string(role)})
		if got.Role != role {
			t.Errorf("org_role %q read as %q", role, got.Role)
		}
	}
}

// A tier this SDK does not know is never guessed upward into one that grants something:
// "superowner" is not "owner", and "Owner" is not either.
func TestOrganizationOfReadsAnUnknownTierAsNone(t *testing.T) {
	for _, raw := range []string{
		`{"org":"org_1","org_role":"superowner"}`,
		`{"org":"org_1","org_role":"Owner"}`,
		`{"org":"org_1","org_role":7}`,
		`{"org":"org_1"}`,
	} {
		org := cboxid.OrganizationOf(claimsJSON(t, raw))
		if org == nil || org.Role != "" {
			t.Errorf("%s: role = %+v, want none", raw, org)
		}
	}
}

func TestOrganizationOfIsNilWithoutAnOrganization(t *testing.T) {
	for _, raw := range []string{`{}`, `{"org":""}`, `{"org":null}`, `{"org":42}`, `{"org_name":"Acme"}`} {
		if org := cboxid.OrganizationOf(claimsJSON(t, raw)); org != nil {
			t.Errorf("%s: OrganizationOf = %+v, want nil", raw, org)
		}
	}
}

func TestActorOfAnOrdinarySession(t *testing.T) {
	for _, raw := range []string{`{"sub":"user-1"}`, `{"sub":"user-1","act":null}`} {
		claims := claimsJSON(t, raw)
		if actor := cboxid.ActorOf(claims); actor != nil {
			t.Errorf("%s: ActorOf = %+v, want nil", raw, actor)
		}
		if cboxid.IsSupportSession(claims) {
			t.Errorf("%s: an ordinary session read as a support session", raw)
		}
	}
}

func TestActorOfASupportSession(t *testing.T) {
	claims := claimsJSON(t, `{"sub":"user-1","act":{"sub":"staff-9","act":{"sub":"staff-1"}}}`)

	actor := cboxid.ActorOf(claims)
	if actor == nil || actor.Subject != "staff-9" {
		t.Fatalf("ActorOf = %+v", actor)
	}
	if actor.Actor == nil || actor.Actor.Subject != "staff-1" || actor.Actor.Actor != nil {
		t.Errorf("nested actor = %+v", actor.Actor)
	}
	if !cboxid.IsSupportSession(claims) {
		t.Errorf("a token with act must read as a support session")
	}
}

// FAIL-CLOSED. An act claim in a shape this SDK cannot read is still an act claim: the
// session is acted, only by whom is unknown. Answering "nobody else is at the keyboard"
// here is the one wrong answer.
func TestIsSupportSessionFailsClosedOnAMalformedAct(t *testing.T) {
	for _, raw := range []string{
		`{"act":"staff-9"}`,
		`{"act":["staff-9"]}`,
		`{"act":{}}`,
		`{"act":{"sub":42}}`,
		`{"act":{"sub":""}}`,
		`{"act":true}`,
		`{"act":0}`,
	} {
		claims := claimsJSON(t, raw)
		if !cboxid.IsSupportSession(claims) {
			t.Errorf("%s: a present act claim must read as a support session", raw)
		}
		if actor := cboxid.ActorOf(claims); actor == nil || actor.Subject != "" {
			t.Errorf("%s: ActorOf = %+v, want an actor with no known subject", raw, actor)
		}
	}
}

// A chain nested far past anything real is cut at the bound, not dropped: the session
// is still acted, and the parse does not recurse without limit.
func TestActorChainIsBounded(t *testing.T) {
	var act any = map[string]any{"sub": "innermost"}
	for i := 0; i < 50; i++ {
		act = map[string]any{"sub": "staff", "act": act}
	}

	actor := cboxid.ActorOf(map[string]any{"act": act})
	depth := 0
	for a := actor; a != nil; a = a.Actor {
		depth++
	}
	if depth != 8 {
		t.Errorf("actor chain depth = %d, want 8", depth)
	}
	if !cboxid.IsSupportSession(map[string]any{"act": act}) {
		t.Errorf("a deep chain must still read as a support session")
	}
}

func TestRolesAndPermissions(t *testing.T) {
	claims := claimsJSON(t, `{"roles":["billing-admin","",3,"viewer"],"permissions":["invoices:read","invoices:*",null]}`)

	if got := cboxid.RolesOf(claims); !slices.Equal(got, []string{"billing-admin", "viewer"}) {
		t.Errorf("RolesOf = %v", got)
	}
	if got := cboxid.PermissionsOf(claims); !slices.Equal(got, []string{"invoices:read", "invoices:*"}) {
		t.Errorf("PermissionsOf = %v", got)
	}
	if !cboxid.HasRole(claims, "viewer") || cboxid.HasRole(claims, "admin") {
		t.Errorf("HasRole is not an exact match")
	}
	if !cboxid.HasPermission(claims, "invoices:read") {
		t.Errorf("HasPermission missed a held permission")
	}
	// No wildcards: nothing on the issuing side mints one, so one is not honoured.
	if cboxid.HasPermission(claims, "invoices:delete") {
		t.Errorf("invoices:* must not grant invoices:delete")
	}
	if cboxid.RolesOf(claimsJSON(t, `{"roles":"viewer"}`)) != nil {
		t.Errorf("a non-list roles claim must read as no roles")
	}
}

// The helpers read a *CboxUser the same way as the claim set it carries, and a nil user
// holds nothing.
func TestClaimHelpersAcceptAUser(t *testing.T) {
	user := &cboxid.CboxUser{ID: "user-1", Claims: claimsJSON(t,
		`{"org":"org_1","org_role":"owner","roles":["viewer"],"permissions":["a:read"],"act":{"sub":"staff-9"}}`)}

	if org := cboxid.OrganizationOf(user); org == nil || org.Role != cboxid.OrganizationRoleOwner {
		t.Errorf("OrganizationOf(user) = %+v", org)
	}
	if !user.HasRole("viewer") || !user.HasPermission("a:read") || !user.IsSupportSession() {
		t.Errorf("user methods disagree with the claims: %+v", user.Claims)
	}
	if actor := cboxid.ActorOf(user); actor == nil || actor.Subject != "staff-9" {
		t.Errorf("ActorOf(user) = %+v", actor)
	}

	var nobody *cboxid.CboxUser
	if cboxid.IsSupportSession(nobody) || cboxid.HasRole(nobody, "viewer") || cboxid.OrganizationOf(nobody) != nil {
		t.Errorf("a nil user must hold nothing")
	}
}

// Authenticate fills the typed fields from the verified claims, so the common case reads
// user.Organization.Role rather than digging in Claims.
func TestAuthenticatePopulatesTypedClaims(t *testing.T) {
	fake := newFakeInstance(t)
	fake.idTokenClaims = map[string]any{
		"org":         "org-1",
		"org_name":    "Acme",
		"org_role":    "developer",
		"roles":       []string{"billing-admin"},
		"permissions": []string{"invoices:create"},
		"act":         map[string]any{"sub": "staff-9"},
		"sid":         "sess-1",
	}

	user, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	want := cboxid.ActiveOrganization{ID: "org-1", Name: "Acme", Role: cboxid.OrganizationRoleDeveloper}
	if user.Organization == nil || *user.Organization != want {
		t.Errorf("Organization = %+v, want %+v", user.Organization, want)
	}
	if !slices.Equal(user.Roles, []string{"billing-admin"}) || !slices.Equal(user.Permissions, []string{"invoices:create"}) {
		t.Errorf("Roles = %v, Permissions = %v", user.Roles, user.Permissions)
	}
	if user.Actor == nil || user.Actor.Subject != "staff-9" || !user.IsSupportSession() {
		t.Errorf("Actor = %+v", user.Actor)
	}
	if user.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", user.SessionID)
	}
}

// sid names the session a back-channel logout ends. UserInfo's body is unsigned, so a
// sid only it carries is not taken: matching logouts against it would let whoever can
// answer as UserInfo decide which session a logout token kills.
func TestSessionIDComesOnlyFromTheIDToken(t *testing.T) {
	fake := newFakeInstance(t)
	fake.userInfo = map[string]any{"sub": "user-1", "sid": "from-userinfo"}

	user, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.SessionID != "" {
		t.Errorf("SessionID = %q, taken from UserInfo", user.SessionID)
	}
}
