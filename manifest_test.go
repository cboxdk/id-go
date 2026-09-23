package cboxid_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// entryByKey finds one role or permission in a posted manifest body by its key.
func entryByKey(t *testing.T, body map[string]any, list, key string) map[string]any {
	t.Helper()
	entries, _ := body[list].([]any)
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		if entry["key"] == key {
			return entry
		}
	}
	t.Fatalf("%s %q missing from the posted manifest: %v", list, key, body[list])
	return nil
}

// The wire key is the whole feature. A staff role pushed without "tenant_assignable":
// false is read by the server as tenant-assignable, and every customer's admin can then
// hand out a role meant only for the vendor's own support staff.
func TestPublishManifestCarriesStaffRolesAndSelfServePermissions(t *testing.T) {
	fake := newFakeInstance(t)
	client, err := cboxid.New(context.Background(), cboxid.Config{
		Issuer:       fake.server.URL,
		ClientID:     clientID,
		ClientSecret: "secret-xyz",
		Permissions: []cboxid.Permission{
			{Key: "parcels:read", Description: "View parcels", TenantAssignable: true},
			{Key: "support:impersonate", Description: "Act as a customer"},
		},
		Roles: []cboxid.Role{
			{Key: "support", Name: "Support", Permissions: []string{"support:impersonate"}, StaffOnly: true},
			{Key: "viewer", Name: "Viewer", Permissions: []string{"parcels:read"}},
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.PublishManifest(context.Background()); err != nil {
		t.Fatalf("publish: %v", err)
	}

	support := entryByKey(t, fake.manifestBody, "roles", "support")
	if value, present := support["tenant_assignable"]; !present || value != false {
		t.Errorf("staff role tenant_assignable = %v (present: %v), want false", value, present)
	}
	// Defaults stay off the wire, so a body for a catalog that uses neither feature is
	// byte-for-byte what it was before either existed.
	viewer := entryByKey(t, fake.manifestBody, "roles", "viewer")
	if value, present := viewer["tenant_assignable"]; present {
		t.Errorf("an ordinary role sent tenant_assignable = %v; the default should be omitted", value)
	}
	parcels := entryByKey(t, fake.manifestBody, "permissions", "parcels:read")
	if value, present := parcels["tenant_assignable"]; !present || value != true {
		t.Errorf("self-serve permission tenant_assignable = %v (present: %v), want true", value, present)
	}
	impersonate := entryByKey(t, fake.manifestBody, "permissions", "support:impersonate")
	if value, present := impersonate["tenant_assignable"]; present {
		t.Errorf("an ordinary permission sent tenant_assignable = %v; the default should be omitted", value)
	}

	if got, want := fake.manifestBody["version"], client.Manifest().Version; got != want {
		t.Errorf("posted version = %v, want %v", got, want)
	}
}

// A Role decoded from the wire shape keeps its meaning both ways, and a non-boolean
// tenant_assignable is refused as the server refuses it, never guessed.
func TestRoleJSONRoundTrip(t *testing.T) {
	var staff cboxid.Role
	if err := json.Unmarshal([]byte(`{"key":"support","name":"Support","permissions":[],"tenant_assignable":false}`), &staff); err != nil {
		t.Fatalf("decode staff role: %v", err)
	}
	if !staff.StaffOnly {
		t.Errorf("tenant_assignable false should decode as StaffOnly")
	}

	var ordinary cboxid.Role
	if err := json.Unmarshal([]byte(`{"key":"viewer","name":"Viewer","permissions":["a:read"]}`), &ordinary); err != nil {
		t.Fatalf("decode ordinary role: %v", err)
	}
	if ordinary.StaffOnly || ordinary.Permissions[0] != "a:read" {
		t.Errorf("unexpected ordinary role: %+v", ordinary)
	}

	encoded, err := json.Marshal(staff)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(string(encoded), `"tenant_assignable":false`) {
		t.Errorf("encoded staff role lost its flag: %s", encoded)
	}

	var bogus cboxid.Role
	err = json.Unmarshal([]byte(`{"key":"support","name":"Support","permissions":[],"tenant_assignable":"no"}`), &bogus)
	if err == nil || !strings.Contains(err.Error(), "tenant_assignable must be true or false") {
		t.Fatalf("want a refusal naming tenant_assignable, got %v", err)
	}
}
