package cboxid_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

const rawOrg = "01j9zq3k4m5n6p7q8r9s0t1v2w"

func TestPublicIDs(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{"org_01J9ZQ3K4M5N6P7Q8R9S0T1V2W", rawOrg, true},
		{rawOrg, "org_01j9zq3k4m5n6p7q8r9s0t1v2w", true},
		{"usr_" + rawOrg, "usr_" + rawOrg, true},
		{rawOrg, rawOrg, true},
		{"org_1", "1", false}, // not a ULID: compared exactly
		{"org-1", "org-1", true},
		{"org_" + rawOrg, "01j9zq3k4m5n6p7q8r9s0t1v2x", false},
		{"", "", false},
		{"org_" + rawOrg, "", false},
	}
	for _, c := range cases {
		if got := cboxid.SameID(c.a, c.b); got != c.same {
			t.Errorf("SameID(%q, %q) = %v, want %v", c.a, c.b, got, c.same)
		}
	}
	if cboxid.RawID("org_01J9ZQ3K4M5N6P7Q8R9S0T1V2W") != rawOrg || cboxid.RawID("org_1") != "org_1" || cboxid.RawID(rawOrg) != rawOrg {
		t.Error("RawID did not unwrap only <prefix>_<ULID>")
	}
	if !cboxid.IsPublicID("org_"+rawOrg) || cboxid.IsPublicID(rawOrg) || cboxid.IsPublicID("org_1") {
		t.Error("IsPublicID misread an id")
	}
}

func TestEventTypesInBothNames(t *testing.T) {
	pairs := map[string]string{
		"organization.member_added": "id.organization.member_added",
		"user.login":                "id.user.signed_in",
		"role.assigned":             "id.role.assigned",
	}
	for old, current := range pairs {
		if got := cboxid.CurrentEventType(old); got != current {
			t.Errorf("CurrentEventType(%q) = %q, want %q", old, got, current)
		}
		if got := cboxid.CurrentEventType(current); got != current {
			t.Errorf("CurrentEventType(%q) = %q, want it unchanged", current, got)
		}
		if got := cboxid.LegacyEventType(current); got != old {
			t.Errorf("LegacyEventType(%q) = %q, want %q", current, got, old)
		}
		if !cboxid.SameEventType(old, current) || !cboxid.SameEventType(current, old) {
			t.Errorf("%q and %q should be the same event", old, current)
		}
	}
	if cboxid.SameEventType("user.created", "user.deleted") || cboxid.SameEventType("", "id.") {
		t.Error("different events matched")
	}
	if cboxid.CurrentEventType("*") != "*" {
		t.Error("the wildcard must stay the wildcard")
	}
}

// v1Client is a manifest client whose APIURL points at the fake instance, which answers
// /v1/app-manifests itself.
func v1Client(t *testing.T, fake *fakeInstance, apiURL string) *cboxid.Client {
	t.Helper()
	client, err := cboxid.New(context.Background(), cboxid.Config{
		Issuer:       fake.server.URL,
		APIURL:       apiURL,
		ClientID:     clientID,
		ClientSecret: "secret-xyz",
		Permissions:  []cboxid.Permission{{Key: "invoices:create"}},
		Roles:        []cboxid.Role{{Key: "billing-admin", Name: "Billing Admin", Permissions: []string{"invoices:create"}}},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestPublishManifestGoesToTheV1APIWhenAPIURLIsSet(t *testing.T) {
	for _, suffix := range []string{"", "/v1", "/v1/", "/"} {
		t.Run("api url"+suffix, func(t *testing.T) {
			fake := newFakeInstance(t)
			summary, err := v1Client(t, fake, fake.server.URL+suffix).PublishManifest(context.Background())
			if err != nil {
				t.Fatalf("publish: %v", err)
			}
			if fake.v1ManifestAuth != "Bearer machine-token" || fake.manifestAuth != "" {
				t.Fatalf("v1 auth %q, legacy auth %q: the push did not go to /v1/app-manifests only", fake.v1ManifestAuth, fake.manifestAuth)
			}
			if summary.RolesDeclared != 1 || summary.PermissionsDeclared != 1 {
				t.Errorf("summary = %+v", summary)
			}
		})
	}
}

func TestPublishManifestWithoutAPIURLStaysOnTheIssuer(t *testing.T) {
	fake := newFakeInstance(t)
	if _, err := manifestClient(t, fake).PublishManifest(context.Background()); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if fake.manifestAuth == "" || fake.v1ManifestAuth != "" {
		t.Fatal("without APIURL the push must go to {issuer}/api/v1/apps/manifest")
	}
}

func TestPublishManifestOnV1SurfacesTheProblemCodeOnly(t *testing.T) {
	fake := newFakeInstance(t)
	fake.v1ManifestStatus = http.StatusForbidden
	_, err := v1Client(t, fake, fake.server.URL).PublishManifest(context.Background())
	if !errors.Is(err, cboxid.ErrManifestRejected) || !strings.Contains(err.Error(), "HTTP 403: insufficient_scope") || strings.Contains(err.Error(), "do-not-expose") {
		t.Fatalf("problem not surfaced safely: %v", err)
	}
}

func TestPublishManifestOnV1RefusesAnotherClientsAcknowledgement(t *testing.T) {
	fake := newFakeInstance(t)
	fake.v1ManifestClientID = "client-other"
	if _, err := v1Client(t, fake, fake.server.URL).PublishManifest(context.Background()); !errors.Is(err, cboxid.ErrManifestRejected) {
		t.Fatalf("an acknowledgement for another client was accepted: %v", err)
	}
}

func TestAPIURLMustBeSecure(t *testing.T) {
	fake := newFakeInstance(t)
	for _, bad := range []string{"http://api.cboxid.com", "https://", "https://api.cboxid.com?x=1", "ftp://api.cboxid.com"} {
		_, err := cboxid.New(context.Background(), cboxid.Config{Issuer: fake.server.URL, ClientID: clientID, APIURL: bad})
		if !errors.Is(err, cboxid.ErrConfiguration) {
			t.Errorf("APIURL %q accepted: %v", bad, err)
		}
	}
}

func TestAuthenticateAcceptsAPrefixedOrganizationForARawClaim(t *testing.T) {
	fake := newFakeInstance(t)
	fake.idTokenClaims = map[string]any{"org": rawOrg}
	user, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"},
		cboxid.Stored{State: "state-1", Nonce: "test-nonce", Organization: "org_" + strings.ToUpper(rawOrg)})
	if err != nil || user.OrganizationID != rawOrg {
		t.Fatalf("prefixed binding refused: %+v %v", user, err)
	}

	fake.idTokenClaims = map[string]any{"org": "01j9zq3k4m5n6p7q8r9s0t1v2x"}
	_, err = fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"},
		cboxid.Stored{State: "state-1", Nonce: "test-nonce", Organization: "org_" + rawOrg})
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("another organization was accepted: %v", err)
	}
}

func TestCheckPermissionsAcceptsPrefixedIDs(t *testing.T) {
	client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		response := grantedDecision()
		response["organization"] = rawOrg
		response["subject"] = map[string]any{"type": "user", "id": "01j9zq3k4m5n6p7q8r9s0t1v2y"}
		return authorizationResponse(r, 200, response), nil
	})
	org := "org_" + rawOrg
	decision, err := client.CheckPermissions(context.Background(), "human-token", "usr_01j9zq3k4m5n6p7q8r9s0t1v2y", &org, []string{"work:read"})
	if err != nil || !decision.Allows("work:read") {
		t.Fatalf("prefixed ids refused: %+v %v", decision, err)
	}

	other := "org_01j9zq3k4m5n6p7q8r9s0t1v2x"
	if _, err := client.CheckPermissions(context.Background(), "human-token", "usr_01j9zq3k4m5n6p7q8r9s0t1v2y", &other, []string{"work:read"}); !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("a decision for another organization was accepted: %v", err)
	}
}
