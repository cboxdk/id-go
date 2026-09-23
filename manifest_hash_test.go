package cboxid

// This is an internal test (package cboxid) so it can assert on the unexported
// canonicalManifestJSON, proving the serialized bytes — not just the hash — are
// byte-for-byte identical to the PHP reference.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type manifestHashCase struct {
	Name        string `json:"name"`
	Permissions []struct {
		Key              string  `json:"key"`
		Description      *string `json:"description"`
		TenantAssignable *bool   `json:"tenant_assignable"`
	} `json:"permissions"`
	Roles []struct {
		Key              string   `json:"key"`
		Name             string   `json:"name"`
		Description      *string  `json:"description"`
		Permissions      []string `json:"permissions"`
		TenantAssignable *bool    `json:"tenant_assignable"`
	} `json:"roles"`
	CanonicalJSON string `json:"canonical_json"`
	SHA256        string `json:"sha256"`
	Version       string `json:"version"`
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// boolOr reads an optional fixture boolean, falling back to the server's default for
// that kind of entry when the fixture leaves it out.
func boolOr(b *bool, fallback bool) bool {
	if b == nil {
		return fallback
	}
	return *b
}

// TestManifestHashMatchesPHPReference locks id-go to the shared cross-SDK fixture,
// generated from Cbox\Id\AccessControl\Manifest\Manifest::checksum in laravel-id.
func TestManifestHashMatchesPHPReference(t *testing.T) {
	data, err := os.ReadFile("testdata/manifest_hash.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture struct {
		Cases []manifestHashCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	// All five shared cases, by name: a fixture that lost the staff_role or
	// self_serve_permission case would otherwise pass while proving nothing about either.
	want := []string{"empty", "basic", "edge_cases", "staff_role", "self_serve_permission"}
	var names []string
	for _, c := range fixture.Cases {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, want) {
		t.Fatalf("fixture cases = %v, want %v", names, want)
	}

	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			permissions := make([]Permission, len(c.Permissions))
			for i, p := range c.Permissions {
				// A permission is self-serve only when it says so (server default false).
				permissions[i] = Permission{Key: p.Key, Description: derefString(p.Description), TenantAssignable: boolOr(p.TenantAssignable, false)}
			}
			roles := make([]Role, len(c.Roles))
			for i, r := range c.Roles {
				// A role is tenant-assignable unless it says otherwise (server default true).
				roles[i] = Role{Key: r.Key, Name: r.Name, Description: derefString(r.Description), Permissions: r.Permissions, StaffOnly: !boolOr(r.TenantAssignable, true)}
			}

			if got := canonicalManifestJSON(permissions, roles); got != c.CanonicalJSON {
				t.Errorf("canonical JSON mismatch\n got: %s\nwant: %s", got, c.CanonicalJSON)
			}
			sum := sha256.Sum256([]byte(canonicalManifestJSON(permissions, roles)))
			if got := hex.EncodeToString(sum[:]); got != c.SHA256 {
				t.Errorf("sha256 = %q, want %q", got, c.SHA256)
			}
			if got := manifestVersion(permissions, roles); got != c.Version {
				t.Errorf("version = %q, want %q", got, c.Version)
			}
			if c.Version != c.SHA256[:16] {
				t.Errorf("fixture inconsistent: version %q != sha256[:16] %q", c.Version, c.SHA256[:16])
			}
		})
	}
}

// The server drops a repeated permission reference before hashing, so a role naming one
// twice must hash as if it named it once — otherwise every deploy of it reads as a change.
func TestManifestHashDeduplicatesRolePermissions(t *testing.T) {
	permissions := []Permission{{Key: "a:read"}, {Key: "a:write"}}
	once := []Role{{Key: "r", Name: "R", Permissions: []string{"a:write", "a:read"}}}
	twice := []Role{{Key: "r", Name: "R", Permissions: []string{"a:read", "a:write", "a:read", "a:write"}}}

	if got, want := canonicalManifestJSON(permissions, twice), canonicalManifestJSON(permissions, once); got != want {
		t.Fatalf("a repeated permission reference changed the canonical form\n got: %s\nwant: %s", got, want)
	}
}
