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
	"slices"
	"sort"
	"strings"
	"unicode/utf16"
)

// scopeAppsManifest is the OAuth scope a client must hold to push an authorization
// manifest. PublishManifest mints a client-credentials token with exactly this scope.
const scopeAppsManifest = "apps.manifest"

// Permission is one authorization permission the app declares. Key is a
// "feature:action" slug (e.g. "invoices:create"); Description is human-facing copy
// shown in the Cbox ID console.
//
// TenantAssignable marks a SELF-SERVE permission: one an organization's own admins may
// grant their members in a custom role. It defaults to false — deny by default — because
// a permission an app never thought about letting customers hand out should not become
// hand-out-able by omission. Only an explicit true is sent (as "tenant_assignable").
type Permission struct {
	Key              string `json:"key"`
	Description      string `json:"description,omitempty"`
	TenantAssignable bool   `json:"tenant_assignable,omitempty"`
}

// Role is one authorization role the app declares. Permissions must reference keys
// of declared Permissions. Cbox ID assigns roles to users and returns them in the
// token's claims; the app decides what each role is allowed to do.
//
// StaffOnly marks a role only the app vendor's own staff may assign — a "support" role
// that can impersonate, say. An organization's admins never see it in their role picker.
// On the wire and in the checksum it is "tenant_assignable": false.
//
// The field is named for the exception rather than the rule on purpose. The server's
// default for a role is tenant-assignable, and Go's zero value is false: a
// TenantAssignable bool would have turned every Role literal written before this field
// existed into a staff-only role, silently, the next time it was published. With
// StaffOnly the zero value means what it always meant, and the checksum of an existing
// catalog does not move.
type Role struct {
	Key         string
	Name        string
	Description string
	Permissions []string
	StaffOnly   bool
}

// roleWire is Role as Cbox ID's manifest endpoint reads it (ManifestParser.php).
type roleWire struct {
	Key         string   `json:"key"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
	// Only ever false on the wire. The key is omitted for an ordinary role, which the
	// server reads as tenant-assignable; a staff role that forgot it would be assignable
	// by every customer's admin.
	TenantAssignable *bool `json:"tenant_assignable,omitempty"`
}

// MarshalJSON writes the role as Cbox ID's manifest endpoint reads it, with a staff
// role carrying "tenant_assignable": false.
func (r Role) MarshalJSON() ([]byte, error) {
	wire := roleWire{Key: r.Key, Name: r.Name, Description: r.Description, Permissions: r.Permissions}
	if r.StaffOnly {
		assignable := false
		wire.TenantAssignable = &assignable
	}
	return json.Marshal(wire)
}

// UnmarshalJSON reads a role in the manifest wire shape. Like the server, it refuses a
// "tenant_assignable" that is not a boolean rather than guessing which way it was meant.
func (r *Role) UnmarshalJSON(data []byte) error {
	var wire struct {
		roleWire
		TenantAssignable json.RawMessage `json:"tenant_assignable"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	staffOnly := false
	if raw := bytes.TrimSpace(wire.TenantAssignable); len(raw) > 0 {
		var assignable bool
		if err := json.Unmarshal(raw, &assignable); err != nil {
			return fmt.Errorf("cboxid: role %q tenant_assignable must be true or false", wire.Key)
		}
		staffOnly = !assignable
	}

	*r = Role{
		Key:         wire.Key,
		Name:        wire.Name,
		Description: wire.Description,
		Permissions: wire.Permissions,
		StaffOnly:   staffOnly,
	}
	return nil
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

// manifestVersion derives a stable content hash from the declared catalog. It is
// byte-for-byte identical to the PHP reference (Cbox\Id\AccessControl\Manifest\
// Manifest::checksum): sha256 over the canonical JSON of {permissions, roles}
// (without the version field), truncated to 16 hex chars. See canonicalManifestJSON.
func manifestVersion(permissions []Permission, roles []Role) string {
	sum := sha256.Sum256([]byte(canonicalManifestJSON(permissions, roles)))
	return hex.EncodeToString(sum[:])[:16]
}

// canonicalManifestJSON serializes {permissions, roles} exactly as the PHP reference's
// json_encode does before hashing: object keys in insertion order, permissions and
// roles sorted by key, each role's permission refs sorted and de-duplicated, an
// absent-or-empty description emitted as null, compact separators, forward slashes
// escaped as "\/", and every non-ASCII rune escaped as "\uXXXX".
//
// "tenant_assignable" appears only where it departs from the default: true on a
// self-serve permission, false on a staff role. So a catalog that uses neither hashes
// exactly as it did before either existed.
func canonicalManifestJSON(permissions []Permission, roles []Role) string {
	type canonPermission struct {
		Key              string  `json:"key"`
		Description      *string `json:"description"`
		TenantAssignable *bool   `json:"tenant_assignable,omitempty"`
	}
	type canonRole struct {
		Key              string   `json:"key"`
		Name             string   `json:"name"`
		Description      *string  `json:"description"`
		Permissions      []string `json:"permissions"`
		TenantAssignable *bool    `json:"tenant_assignable,omitempty"`
	}

	assignable, staffOnly := true, false

	sortedPermissions := append([]Permission(nil), permissions...)
	sort.Slice(sortedPermissions, func(i, j int) bool { return sortedPermissions[i].Key < sortedPermissions[j].Key })
	canonPermissions := make([]canonPermission, len(sortedPermissions))
	for i, p := range sortedPermissions {
		canonPermissions[i] = canonPermission{Key: p.Key, Description: emptyToNull(p.Description)}
		if p.TenantAssignable {
			canonPermissions[i].TenantAssignable = &assignable
		}
	}

	sortedRoles := append([]Role(nil), roles...)
	sort.Slice(sortedRoles, func(i, j int) bool { return sortedRoles[i].Key < sortedRoles[j].Key })
	canonRoles := make([]canonRole, len(sortedRoles))
	for i, r := range sortedRoles {
		perms := append([]string(nil), r.Permissions...)
		sort.Strings(perms)
		// The server's parser drops a repeated reference before it hashes, so a role
		// that names one twice must hash as if it named it once — or every deploy of it
		// looks like a change.
		perms = slices.Compact(perms)
		if perms == nil {
			perms = []string{}
		}
		canonRoles[i] = canonRole{Key: r.Key, Name: r.Name, Description: emptyToNull(r.Description), Permissions: perms}
		if r.StaffOnly {
			canonRoles[i].TenantAssignable = &staffOnly
		}
	}

	canonical := struct {
		Permissions []canonPermission `json:"permissions"`
		Roles       []canonRole       `json:"roles"`
	}{Permissions: canonPermissions, Roles: canonRoles}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // PHP leaves <, >, & unescaped; escapeLikePHP handles the rest.
	if err := enc.Encode(canonical); err != nil {
		return ""
	}
	return escapeLikePHP(bytes.TrimRight(buf.Bytes(), "\n"))
}

// emptyToNull maps an absent or empty description to a JSON null, matching PHP.
func emptyToNull(description string) *string {
	if description == "" {
		return nil
	}
	return &description
}

// escapeLikePHP applies PHP json_encode's default "\/" slash escaping and "\uXXXX"
// non-ASCII escaping to already-valid JSON bytes.
func escapeLikePHP(raw []byte) string {
	var sb strings.Builder
	for _, r := range string(raw) {
		switch {
		case r == '/':
			sb.WriteString(`\/`)
		case r < 0x80:
			sb.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			high, low := utf16.EncodeRune(r)
			fmt.Fprintf(&sb, `\u%04x\u%04x`, high, low)
		}
	}
	return sb.String()
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
