package cboxid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// scopeAppsManifest is the OAuth scope a client must hold to push an authorization
// manifest. PublishManifest mints a client-credentials token with exactly this scope.
const scopeAppsManifest = "apps.manifest"

// Permission is one authorization permission the app declares. Key is a
// "feature:action" slug (e.g. "invoices:create"); Description is human-facing copy
// shown in the Cbox ID console.
type Permission struct {
	Key         string `json:"key"`
	Description string `json:"description,omitempty"`
}

// Role is one authorization role the app declares. Permissions must reference keys
// of declared Permissions. Cbox ID assigns roles to users and returns them in the
// token's claims; the app decides what each role is allowed to do.
type Role struct {
	Key         string   `json:"key"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

// Manifest is the app's declared authorization catalog as it is sent to Cbox ID:
// its permissions and roles plus a content-derived Version, so republishing an
// unchanged catalog is a server-side no-op. Its JSON shape is the contract shared by
// every Cbox ID SDK.
type Manifest struct {
	Permissions []Permission `json:"permissions"`
	Roles       []Role       `json:"roles"`
	Version     string       `json:"version"`
}

// Summary is Cbox ID's response to a manifest push. Unchanged is true when the
// pushed catalog matched what was already synced. Orphaned* list keys the app once
// declared but dropped — Cbox ID keeps and flags them rather than deleting them.
type Summary struct {
	Unchanged           bool     `json:"unchanged"`
	RolesDeclared       int      `json:"roles_declared"`
	PermissionsDeclared int      `json:"permissions_declared"`
	OrphanedRoles       []string `json:"orphaned_roles,omitempty"`
	OrphanedPermissions []string `json:"orphaned_permissions,omitempty"`
}

// Manifest returns the manifest that PublishManifest would send: the configured
// permissions and roles with a stable content hash as its version. The hash is the
// first 16 hex chars of the SHA-256 over the JSON-encoded permissions+roles, so an
// unchanged catalog yields an unchanged version.
func (c *Client) Manifest() Manifest {
	permissions := c.cfg.Permissions
	if permissions == nil {
		permissions = []Permission{}
	}
	roles := c.cfg.Roles
	if roles == nil {
		roles = []Role{}
	}

	body := Manifest{Permissions: permissions, Roles: roles}
	body.Version = manifestVersion(permissions, roles)
	return body
}

// manifestVersion derives a stable content hash from the declared catalog. It mirrors
// the PHP reference: sha256 over the JSON of {permissions, roles} (without the version
// field), truncated to 16 hex chars.
func manifestVersion(permissions []Permission, roles []Role) string {
	encoded, err := json.Marshal(struct {
		Permissions []Permission `json:"permissions"`
		Roles       []Role       `json:"roles"`
	}{Permissions: permissions, Roles: roles})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])[:16]
}

// PublishManifest pushes this app's declared roles and permissions (Config.Roles and
// Config.Permissions) to Cbox ID, and returns the server's sync summary. Run it on
// deploy so the Cbox ID console always reflects the app's current catalog; it is
// idempotent — republishing an unchanged manifest is a no-op.
//
// It mints a client-credentials token scoped to apps.manifest, then POSTs the
// manifest to {issuer}/api/v1/apps/manifest with that bearer token. Requires a
// ClientSecret and a client that holds the apps.manifest scope. It returns
// ErrConfiguration when nothing is declared or credentials are missing, and wraps
// ErrManifestRejected when Cbox ID refuses the push.
func (c *Client) PublishManifest(ctx context.Context) (Summary, error) {
	if c.cfg.ClientSecret == "" {
		return Summary{}, fmt.Errorf("%w: PublishManifest requires a ClientSecret", ErrConfiguration)
	}

	manifest := c.Manifest()
	if len(manifest.Permissions) == 0 && len(manifest.Roles) == 0 {
		return Summary{}, fmt.Errorf("%w: no roles or permissions declared to publish", ErrConfiguration)
	}

	token, err := c.MachineToken(ctx, MachineTokenParams{Scopes: []string{scopeAppsManifest}})
	if err != nil {
		return Summary{}, err
	}

	body, err := json.Marshal(manifest)
	if err != nil {
		return Summary{}, fmt.Errorf("%w: could not encode the manifest: %v", ErrConfiguration, err)
	}

	endpoint := strings.TrimRight(c.cfg.Issuer, "/") + "/api/v1/apps/manifest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Summary{}, fmt.Errorf("%w: %v", ErrManifestRejected, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := c.cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Summary{}, fmt.Errorf("%w: manifest request failed: %v", ErrManifestRejected, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Summary{}, fmt.Errorf("%w: HTTP %d %s", ErrManifestRejected, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var summary Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return Summary{}, fmt.Errorf("%w: could not parse the sync summary: %v", ErrManifestRejected, err)
	}
	return summary, nil
}
