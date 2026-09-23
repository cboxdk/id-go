package cboxid_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

func TestAuthorizationRequestCarriesOrganizationParams(t *testing.T) {
	fake := newFakeInstance(t)

	req, err := fake.client(t).CreateAuthorizationRequest(cboxid.AuthParams{Organization: "org_2"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	q := mustQuery(t, req.URL)
	if q.Get("organization") != "org_2" {
		t.Errorf("organization = %q", q.Get("organization"))
	}
	if req.Organization != "org_2" {
		t.Errorf("the bound organization was not echoed for persisting: %q", req.Organization)
	}

	req, err = fake.client(t).CreateAuthorizationRequest(cboxid.AuthParams{
		OrganizationHint: "org_3",
		Prompt:           []cboxid.Prompt{cboxid.PromptSelectOrganization, cboxid.PromptLogin},
	})
	if err != nil {
		t.Fatalf("create with hint: %v", err)
	}
	q = mustQuery(t, req.URL)
	if q.Get("organization_hint") != "org_3" || q.Get("prompt") != "select_organization login" {
		t.Errorf("organization_hint = %q, prompt = %q", q.Get("organization_hint"), q.Get("prompt"))
	}
	if q.Has("organization") || req.Organization != "" {
		t.Errorf("a hint must not bind the sign-in: %v, %q", q, req.Organization)
	}
}

// Go's zero value means "not set": an unset organization is left off the URL entirely,
// never sent as a parameter that names nothing.
func TestAuthorizationRequestOmitsUnsetOrganizationParams(t *testing.T) {
	fake := newFakeInstance(t)

	req, err := fake.client(t).CreateAuthorizationRequest(cboxid.AuthParams{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	q := mustQuery(t, req.URL)
	for _, param := range []string{"organization", "organization_hint", "prompt"} {
		if q.Has(param) {
			t.Errorf("%s sent without being set: %q", param, q.Get(param))
		}
	}
}

func TestPromptValuesAreDeduplicated(t *testing.T) {
	fake := newFakeInstance(t)

	req, err := fake.client(t).CreateAuthorizationRequest(cboxid.AuthParams{
		Prompt: []cboxid.Prompt{cboxid.PromptLogin, "consent login", cboxid.PromptConsent},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := mustQuery(t, req.URL).Get("prompt"); got != "login consent" {
		t.Errorf("prompt = %q, want %q", got, "login consent")
	}
}

// Each of these could only fail at the server, after a full redirect, as a generic error
// far from the line that built it. They are refused before a URL exists, and the message
// says what to do instead.
func TestAuthorizationRequestRefusesContradictoryParams(t *testing.T) {
	cases := map[string]struct {
		params cboxid.AuthParams
		want   string
	}{
		"organization with select_organization": {
			params: cboxid.AuthParams{Organization: "org_2", Prompt: []cboxid.Prompt{cboxid.PromptSelectOrganization}},
			want:   "use AuthParams.OrganizationHint to preselect",
		},
		"organization with create_organization": {
			params: cboxid.AuthParams{Organization: "org_2", Prompt: []cboxid.Prompt{cboxid.PromptLogin, cboxid.PromptCreateOrganization}},
			want:   "PromptCreateOrganization creates a new one",
		},
		"none with another prompt": {
			params: cboxid.AuthParams{Prompt: []cboxid.Prompt{cboxid.PromptNone, cboxid.PromptLogin}},
			want:   "PromptNone cannot be combined",
		},
		"none hidden in one space-separated value": {
			params: cboxid.AuthParams{Prompt: []cboxid.Prompt{"none login"}},
			want:   "PromptNone cannot be combined",
		},
	}

	fake := newFakeInstance(t)
	client := fake.client(t)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req, err := client.CreateAuthorizationRequest(tc.params)
			if !errors.Is(err, cboxid.ErrConfiguration) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want ErrConfiguration containing %q, got %v", tc.want, err)
			}
			if req.URL != "" {
				t.Errorf("a refused request still produced a URL: %s", req.URL)
			}
		})
	}

	// None on its own, and a hint beside the picker, are fine.
	for _, params := range []cboxid.AuthParams{
		{Prompt: []cboxid.Prompt{cboxid.PromptNone}},
		{Prompt: []cboxid.Prompt{cboxid.PromptNone, cboxid.PromptNone}},
		{OrganizationHint: "org_2", Prompt: []cboxid.Prompt{cboxid.PromptSelectOrganization}},
		{Prompt: []cboxid.Prompt{cboxid.PromptCreateOrganization}},
	} {
		if _, err := client.CreateAuthorizationRequest(params); err != nil {
			t.Errorf("%+v refused: %v", params, err)
		}
	}
}

func TestSwitchOrganization(t *testing.T) {
	fake := newFakeInstance(t)
	client := fake.client(t)

	req, err := client.SwitchOrganization("org_2", cboxid.AuthParams{LoginHint: "ada@acme.com"})
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	q := mustQuery(t, req.URL)
	if q.Get("organization") != "org_2" || q.Get("login_hint") != "ada@acme.com" {
		t.Errorf("switch URL = %v", q)
	}
	if req.Organization != "org_2" || req.State == "" || req.CodeVerifier == "" || req.Nonce == "" {
		t.Errorf("switch request = %+v", req)
	}

	for name, tc := range map[string]struct {
		id     string
		params cboxid.AuthParams
		want   string
	}{
		"empty id":        {id: "", want: "needs the id of the organization"},
		"organization":    {id: "org_2", params: cboxid.AuthParams{Organization: "org_3"}, want: "first argument"},
		"hint":            {id: "org_2", params: cboxid.AuthParams{OrganizationHint: "org_3"}, want: "first argument"},
		"with the picker": {id: "org_2", params: cboxid.AuthParams{Prompt: []cboxid.Prompt{cboxid.PromptSelectOrganization}}, want: "nothing to choose"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client.SwitchOrganization(tc.id, tc.params)
			if !errors.Is(err, cboxid.ErrConfiguration) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want ErrConfiguration containing %q, got %v", tc.want, err)
			}
		})
	}
}

// The binding is checked, not trusted. An instance that predates the organization
// parameter ignores it and returns tokens for whichever organization the session already
// had; an app that switched to org_2 would then show org_2's name over org-1's data.
func TestAuthenticateRefusesTokensForAnotherOrganization(t *testing.T) {
	fake := newFakeInstance(t) // its tokens are for org-1

	bound := stored
	bound.Organization = "org_2"
	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, bound)

	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("want ErrAuthentication, got %v", err)
	}
	for _, want := range []string{"bound to organization org_2", "tokens are for org-1", "may not support organization selection"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}

func TestAuthenticateRefusesUnboundTokensForABoundSignIn(t *testing.T) {
	fake := newFakeInstance(t)
	fake.userInfo = map[string]any{"sub": "user-1"} // no org anywhere

	bound := stored
	bound.Organization = "org_2"
	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, bound)

	if !errors.Is(err, cboxid.ErrAuthentication) || !strings.Contains(err.Error(), "tokens are for no organization") {
		t.Fatalf("want a refusal naming no organization, got %v", err)
	}
}

func TestAuthenticateAcceptsTokensForTheBoundOrganization(t *testing.T) {
	fake := newFakeInstance(t)

	bound := stored
	bound.Organization = "org-1"
	user, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, bound)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.OrganizationID != "org-1" {
		t.Errorf("org = %q", user.OrganizationID)
	}
}

// access_denied after a switch means "not a member of that organization", which an app
// answers by staying where it is — so the code has to reach it as data, not prose.
func TestCallbackErrorIsStructured(t *testing.T) {
	fake := newFakeInstance(t)

	_, err := fake.client(t).Authenticate(context.Background(), cboxid.Callback{
		State:            "state-1",
		Error:            "access_denied",
		ErrorDescription: "Not a member of that organization.",
	}, stored)

	var oauthErr *cboxid.OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("want an *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.Code != "access_denied" || oauthErr.Description != "Not a member of that organization." || oauthErr.Op != "authorization" {
		t.Errorf("OAuthError = %+v", oauthErr)
	}
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Errorf("a callback error must still be ErrAuthentication")
	}
}
