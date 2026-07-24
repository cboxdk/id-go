package cboxid

// This is an internal test (package cboxid) so it can assert on the unexported
// canonicalManifestJSON, proving the serialized bytes — not just the hash — are
// byte-for-byte identical to the PHP reference.

import (
	"encoding/json"
	"os"
	"testing"
)

type manifestHashCase struct {
	Name        string `json:"name"`
	Permissions []struct {
		Key         string  `json:"key"`
		Description *string `json:"description"`
	} `json:"permissions"`
	Roles []struct {
		Key         string   `json:"key"`
		Name        string   `json:"name"`
		Description *string  `json:"description"`
		Permissions []string `json:"permissions"`
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
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture had no cases")
	}

	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			permissions := make([]Permission, len(c.Permissions))
			for i, p := range c.Permissions {
				permissions[i] = Permission{Key: p.Key, Description: derefString(p.Description)}
			}
			roles := make([]Role, len(c.Roles))
			for i, r := range c.Roles {
				roles[i] = Role{Key: r.Key, Name: r.Name, Description: derefString(r.Description), Permissions: r.Permissions}
			}

			if got := canonicalManifestJSON(permissions, roles); got != c.CanonicalJSON {
				t.Errorf("canonical JSON mismatch\n got: %s\nwant: %s", got, c.CanonicalJSON)
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
