package cboxid_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

type authorizationTransport func(*http.Request) (*http.Response, error)

func (f authorizationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func authorizationResponse(r *http.Request, status int, body any) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}
}
func authorizationClient(t *testing.T, handler authorizationTransport) *cboxid.Client {
	t.Helper()
	fake := newFakeInstance(t)
	client, err := cboxid.New(context.Background(), cboxid.Config{Issuer: fake.server.URL, ClientID: clientID, ClientSecret: "fixture-secret", Permissions: []cboxid.Permission{{Key: "work:read"}}, Roles: []cboxid.Role{{Key: "reader", Name: "Reader", Permissions: []string{"work:read"}}}, HTTPClient: &http.Client{Transport: authorizationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oauth/decisions" || r.URL.Path == "/api/v1/apps/manifest" || r.URL.Path == "/credential-trap" {
			return handler(r)
		}
		return http.DefaultTransport.RoundTrip(r)
	})}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func grantedDecision() map[string]any {
	return map[string]any{"mode": "rbac", "subject": map[string]any{"type": "user", "id": "person"}, "organization": "org", "client_id": clientID, "organization_active": true, "org_role": "member", "allowed": true, "results": []any{map[string]any{"permission": "work:read", "allowed": true}}}
}
func TestCheckPermissionsBindsRequestAndObservesImmediateRevocation(t *testing.T) {
	calls := 0
	client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer human-token" {
			t.Fatal("wrong authorization request")
		}
		var request map[string]any
		if json.NewDecoder(r.Body).Decode(&request) != nil || request["subject"] != "person" || request["org"] != "org" {
			t.Fatal("unbound request")
		}
		permissions := request["permission"].([]any)
		if len(permissions) != 1 || permissions[0] != "work:read" {
			t.Fatal("permissions not normalized")
		}
		response := grantedDecision()
		if calls == 2 {
			response["org_role"] = "admin"
			response["allowed"] = false
			response["results"] = []any{map[string]any{"permission": "work:read", "allowed": false}}
		}
		if calls > 2 {
			response["organization_active"] = false
			response["allowed"] = false
		}
		return authorizationResponse(r, 200, response), nil
	})
	org := "org"
	first, err := client.CheckPermissions(context.Background(), "human-token", "person", &org, []string{"work:read", "work:read"})
	if err != nil || !first.Allows("work:read") || !first.Allowed() || first.Allows("unrequested:write") {
		t.Fatalf("first decision: %+v %v", first, err)
	}
	second, err := client.CheckPermissions(context.Background(), "human-token", "person", &org, []string{"work:read"})
	if err != nil || second.Allowed() || second.Allows("work:read") || calls != 2 {
		t.Fatalf("revocation not observed: %+v %v", second, err)
	}
	third, err := client.CheckPermissions(context.Background(), "human-token", "person", &org, []string{"work:read"})
	if err != nil || third.Allowed() || third.Allows("work:read") || calls != 3 {
		t.Fatalf("membership revocation not observed: %+v %v", third, err)
	}
}
func TestCheckPermissionsRejectsUnboundMalformedOrUnavailableResponses(t *testing.T) {
	cases := map[string]func(map[string]any){
		"subject":              func(d map[string]any) { d["subject"] = map[string]any{"type": "user", "id": "other"} },
		"machine":              func(d map[string]any) { d["subject"] = map[string]any{"type": "client", "id": "person"} },
		"organization":         func(d map[string]any) { d["organization"] = "other" },
		"client":               func(d map[string]any) { d["client_id"] = "other" },
		"mode":                 func(d map[string]any) { d["mode"] = "scope" },
		"missing role":         func(d map[string]any) { delete(d, "org_role") },
		"role":                 func(d map[string]any) { d["org_role"] = "superuser" },
		"missing organization": func(d map[string]any) { delete(d, "organization") },
		"active string":        func(d map[string]any) { d["organization_active"] = "true" },
		"missing result":       func(d map[string]any) { d["results"] = []any{} },
		"foreign result": func(d map[string]any) {
			d["results"] = []any{map[string]any{"permission": "other:read", "allowed": true}}
		},
		"null result": func(d map[string]any) {
			d["results"] = []any{map[string]any{"permission": "work:read", "allowed": nil}}
		},
		"inconsistent":      func(d map[string]any) { d["allowed"] = false },
		"inactive positive": func(d map[string]any) { d["organization_active"] = false },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
				d := grantedDecision()
				change(d)
				return authorizationResponse(r, 200, d), nil
			})
			org := "org"
			d, err := client.CheckPermissions(context.Background(), "human-token", "person", &org, []string{"work:read"})
			if !errors.Is(err, cboxid.ErrAuthentication) || d.Allowed() {
				t.Fatalf("accepted %s: %+v %v", name, d, err)
			}
		})
	}
	for _, status := range []int{302, 401, 403, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				res := authorizationResponse(r, status, grantedDecision())
				res.Header.Set("Location", "/credential-trap")
				return res, nil
			})
			org := "org"
			d, err := client.CheckPermissions(context.Background(), "human-token", "person", &org, []string{"work:read"})
			if err == nil || d.Allowed() || calls != 1 {
				t.Fatal("accepted failure or followed redirect")
			}
		})
	}
}
func TestCheckPermissionsBoundsBodiesAndSanitizesTransportErrors(t *testing.T) {
	for _, kind := range []string{"oversized", "transport", "trailing-json"} {
		t.Run(kind, func(t *testing.T) {
			client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
				if kind == "transport" {
					return nil, errors.New("secret-human-token must never escape")
				}
				response := authorizationResponse(r, 200, grantedDecision())
				raw, _ := io.ReadAll(response.Body)
				if kind == "oversized" {
					raw = append(raw, []byte(strings.Repeat(" ", 65537))...)
				} else {
					raw = append(raw, []byte("{}")...)
				}
				response.Body = io.NopCloser(strings.NewReader(string(raw)))
				return response, nil
			})
			org := "org"
			_, err := client.CheckPermissions(context.Background(), "secret-human-token", "person", &org, []string{"work:read"})
			if !errors.Is(err, cboxid.ErrAuthentication) || strings.Contains(err.Error(), "secret-human-token") {
				t.Fatalf("unsafe error %v", err)
			}
		})
	}
}
func TestCheckPermissionsRejectsInvalidInputBeforeTransport(t *testing.T) {
	calls := 0
	client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return authorizationResponse(r, 200, grantedDecision()), nil
	})
	org := "org"
	for _, token := range []string{"", "bad token", "bad\nheader", strings.Repeat("x", 32769)} {
		_, err := client.CheckPermissions(context.Background(), token, "person", &org, []string{"work:read"})
		if !errors.Is(err, cboxid.ErrConfiguration) {
			t.Fatal("accepted token")
		}
	}
	_, err := client.CheckPermissions(context.Background(), "token", "person", &org, nil)
	if !errors.Is(err, cboxid.ErrConfiguration) || calls != 0 {
		t.Fatal("invalid request reached transport")
	}
}

func TestCheckPermissionsNeverPromotesSharedAdminAndSupportsNoOrganization(t *testing.T) {
	client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
		d := grantedDecision()
		d["organization"] = nil
		d["org_role"] = "admin"
		d["allowed"] = false
		d["results"] = []any{map[string]any{"permission": "work:read", "allowed": false}}
		return authorizationResponse(r, 200, d), nil
	})
	d, err := client.CheckPermissions(context.Background(), "token", "person", nil, []string{"work:read"})
	if err != nil || d.Allowed() || d.Allows("work:read") || d.Organization != nil {
		t.Fatalf("role escalation: %+v %v", d, err)
	}
}

func TestCheckPermissionsRejectsDuplicateResults(t *testing.T) {
	client := authorizationClient(t, func(r *http.Request) (*http.Response, error) {
		d := grantedDecision()
		d["results"] = []any{map[string]any{"permission": "work:read", "allowed": true}, map[string]any{"permission": "work:read", "allowed": true}}
		return authorizationResponse(r, 200, d), nil
	})
	org := "org"
	_, err := client.CheckPermissions(context.Background(), "token", "person", &org, []string{"work:read", "work:write"})
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatal("accepted duplicated results")
	}
}
