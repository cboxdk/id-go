package cboxid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PermissionDecision is a live decision bound to a single subject, organization and app.
// It never grants access from a shared organization role alone.
type PermissionDecision struct {
	Subject            string
	Organization       *string
	ClientID           string
	OrganizationRole   *string
	OrganizationActive bool
	permissions        map[string]bool
}

// Allows fails closed for inactive membership and permissions that were not checked.
func (d PermissionDecision) Allows(permission string) bool {
	return d.OrganizationActive && d.permissions[permission]
}

// Allowed reports whether every requested permission is currently allowed.
func (d PermissionDecision) Allowed() bool {
	if !d.OrganizationActive || len(d.permissions) == 0 {
		return false
	}
	for _, allowed := range d.permissions {
		if !allowed {
			return false
		}
	}
	return true
}

// CheckPermissions obtains a fresh human authorization decision for every call. The
// caller must pass the current authenticated subject and request-bound organization;
// never substitute a default workspace or reuse this decision across requests/jobs.
// Errors fail closed and never include the bearer token or upstream response body.
func (c *Client) CheckPermissions(ctx context.Context, accessToken, subject string, organization *string, permissions []string) (PermissionDecision, error) {
	invalid := func() (PermissionDecision, error) {
		return PermissionDecision{}, fmt.Errorf("%w: invalid permission decision request", ErrConfiguration)
	}
	if c.cfg.ClientID == "" || subject == "" || (organization != nil && *organization == "") || accessToken == "" || len(accessToken) > 32768 || len(permissions) == 0 || len(permissions) > 50 {
		return invalid()
	}
	for _, r := range accessToken {
		if r <= 32 || r == 127 {
			return invalid()
		}
	}
	wanted := make(map[string]bool, len(permissions))
	unique := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		if strings.TrimSpace(permission) == "" || len(permission) > 255 {
			return invalid()
		}
		if !wanted[permission] {
			wanted[permission] = true
			unique = append(unique, permission)
		}
	}
	body, _ := json.Marshal(struct {
		Permission []string `json:"permission"`
		Subject    string   `json:"subject"`
		Org        *string  `json:"org"`
	}{unique, subject, organization})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.Issuer, "/")+"/oauth/decisions", bytes.NewReader(body))
	if err != nil {
		return invalid()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	failure := func() (PermissionDecision, error) {
		return PermissionDecision{}, fmt.Errorf("%w: permission decision could not be verified", ErrAuthentication)
	}
	resp, err := c.authorizationHTTPClient().Do(req)
	if err != nil {
		return failure()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return failure()
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return failure()
	}
	var data struct {
		Mode    string `json:"mode"`
		Subject *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"subject"`
		Organization json.RawMessage `json:"organization"`
		ClientID     string          `json:"client_id"`
		Active       *bool           `json:"organization_active"`
		Allowed      *bool           `json:"allowed"`
		Role         json.RawMessage `json:"org_role"`
		Results      *[]struct {
			Permission string `json:"permission"`
			Allowed    *bool  `json:"allowed"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Mode != "rbac" || data.Subject == nil || data.Subject.Type != "user" || !SameID(data.Subject.ID, subject) || data.ClientID != c.cfg.ClientID || len(data.Organization) == 0 || len(data.Role) == 0 || data.Active == nil || data.Allowed == nil || data.Results == nil || len(*data.Results) != len(unique) {
		return failure()
	}
	var org, role *string
	if json.Unmarshal(data.Organization, &org) != nil || json.Unmarshal(data.Role, &role) != nil || !equalOptionalString(org, organization) {
		return failure()
	}
	if role != nil && *role != "owner" && *role != "admin" && *role != "member" && *role != "developer" && *role != "viewer" {
		return failure()
	}
	checks := make(map[string]bool, len(unique))
	for _, result := range *data.Results {
		if !wanted[result.Permission] || result.Allowed == nil {
			return failure()
		}
		if _, seen := checks[result.Permission]; seen {
			return failure()
		}
		checks[result.Permission] = *result.Allowed
	}
	decision := PermissionDecision{Subject: subject, Organization: org, ClientID: c.cfg.ClientID, OrganizationRole: role, OrganizationActive: *data.Active, permissions: checks}
	if decision.Allowed() != *data.Allowed {
		return failure()
	}
	return decision, nil
}

// equalOptionalString compares two optional ids. Both absent match; a prefixed public id
// (org_01J9Z…) matches its raw form, since the caller may hold either spelling.
func equalOptionalString(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && (*a == *b || SameID(*a, *b)))
}

// Authorization transports are bounded and never redirect credentials. Clone the
// client's configuration so a shared caller-provided HTTP client is not mutated.
func (c *Client) authorizationHTTPClient() *http.Client {
	source := c.cfg.HTTPClient
	if source == nil {
		source = http.DefaultClient
	}
	client := *source
	if client.Timeout <= 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}
