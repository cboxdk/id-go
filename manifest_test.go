package cboxid_test

import (
	"context"
	"errors"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

// manifestClient builds a client whose config declares one permission and one role,
// against the running fake instance.
func manifestClient(t *testing.T, fake *fakeInstance) *cboxid.Client {
	t.Helper()
	client, err := cboxid.New(context.Background(), cboxid.Config{
		Issuer:       fake.server.URL,
		ClientID:     clientID,
		ClientSecret: "secret-xyz",
		RedirectURI:  "https://app.test/auth/callback",
		Permissions: []cboxid.Permission{
			{Key: "invoices:create", Description: "Create invoices"},
		},
		Roles: []cboxid.Role{
			{Key: "billing-admin", Name: "Billing Admin", Description: "Full billing access", Permissions: []string{"invoices:create"}},
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestManifestHasContentDerivedVersion(t *testing.T) {
	fake := newFakeInstance(t)
	manifest := manifestClient(t, fake).Manifest()

	if len(manifest.Permissions) != 1 || len(manifest.Roles) != 1 {
		t.Fatalf("unexpected catalog: %+v", manifest)
	}
	if manifest.Version == "" {
		t.Errorf("version should be a non-empty content hash")
	}
	if manifest.Roles[0].Permissions[0] != "invoices:create" {
		t.Errorf("role permission = %q", manifest.Roles[0].Permissions[0])
	}
}

func TestPublishManifest(t *testing.T) {
	fake := newFakeInstance(t)
	summary, err := manifestClient(t, fake).PublishManifest(context.Background())
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	if summary.Unchanged {
		t.Errorf("expected a changed sync, got unchanged")
	}
	if summary.RolesDeclared != 1 || summary.PermissionsDeclared != 1 {
		t.Errorf("summary = %+v", summary)
	}

	// The token was minted client-credentials with exactly the apps.manifest scope…
	if fake.tokenScope != "apps.manifest" {
		t.Errorf("token scope = %q, want apps.manifest", fake.tokenScope)
	}
	// …and the manifest POST carried that bearer token and the declared role.
	if fake.manifestAuth != "Bearer machine-token" {
		t.Errorf("manifest Authorization = %q", fake.manifestAuth)
	}
	roles, _ := fake.manifestBody["roles"].([]any)
	if len(roles) != 1 {
		t.Fatalf("manifest body roles = %v", fake.manifestBody["roles"])
	}
	first, _ := roles[0].(map[string]any)
	if first["key"] != "billing-admin" {
		t.Errorf("posted role key = %v", first["key"])
	}
	if version, _ := fake.manifestBody["version"].(string); version == "" {
		t.Errorf("manifest body carried no version")
	}
}

func TestPublishManifestRejected(t *testing.T) {
	fake := newFakeInstance(t)
	fake.manifestStatus = 403
	_, err := manifestClient(t, fake).PublishManifest(context.Background())
	if !errors.Is(err, cboxid.ErrManifestRejected) {
		t.Fatalf("want ErrManifestRejected, got %v", err)
	}
}

func TestPublishManifestRequiresDeclaredCatalog(t *testing.T) {
	fake := newFakeInstance(t)
	// A client with no declared roles/permissions has nothing to publish.
	_, err := fake.client(t).PublishManifest(context.Background())
	if !errors.Is(err, cboxid.ErrConfiguration) {
		t.Fatalf("want ErrConfiguration, got %v", err)
	}
}
