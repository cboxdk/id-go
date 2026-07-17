package cboxid_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	cboxid "github.com/cboxdk/id-go"
)

const clientID = "client-abc"

// fakeInstance is a real Cbox ID stand-in: a running HTTP server with a real RSA
// keypair that serves discovery + JWKS, signs genuine id_tokens, and answers the
// token / userinfo / introspection endpoints.
type fakeInstance struct {
	server        *httptest.Server
	signer        jose.Signer
	nonce         string
	idTokenClaims map[string]any // overrides for the default id_token

	// Recorded by the /token and /api/v1/apps/manifest handlers for assertions.
	tokenScope     string
	manifestAuth   string
	manifestBody   map[string]any
	manifestStatus int // response status for the manifest endpoint; 0 => 200
}

func newFakeInstance(t *testing.T) *fakeInstance {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "test-key"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	fake := &fakeInstance{signer: signer, nonce: "test-nonce"}

	mux := http.NewServeMux()
	fake.server = httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                        fake.server.URL,
			"authorization_endpoint":        fake.server.URL + "/authorize",
			"token_endpoint":                fake.server.URL + "/token",
			"jwks_uri":                      fake.server.URL + "/jwks",
			"userinfo_endpoint":             fake.server.URL + "/userinfo",
			"introspection_endpoint":        fake.server.URL + "/introspect",
			"end_session_endpoint":          fake.server.URL + "/logout",
			"device_authorization_endpoint": fake.server.URL + "/device_authorization",
		})
	})
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"device_code":               "device-abc",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          fake.server.URL + "/device",
			"verification_uri_complete": fake.server.URL + "/device?user_code=WDJB-MJHT",
			"expires_in":                600,
			"interval":                  5,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "client_credentials" {
			fake.tokenScope = r.Form.Get("scope")
			writeJSON(w, map[string]any{"access_token": "machine-token", "token_type": "Bearer"})
			return
		}
		writeJSON(w, map[string]any{
			"access_token":  "access-abc",
			"refresh_token": "refresh-abc",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"id_token":      fake.signIDToken(t, fake.idTokenClaims),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"sub": "user-1", "email": "ada@acme.com", "name": "Ada", "org": "org-1"})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"active": true, "sub": "user-1", "scope": "openid"})
	})
	mux.HandleFunc("/api/v1/apps/manifest", func(w http.ResponseWriter, r *http.Request) {
		fake.manifestAuth = r.Header.Get("Authorization")
		fake.manifestBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&fake.manifestBody)
		if fake.manifestStatus != 0 {
			w.WriteHeader(fake.manifestStatus)
			writeJSON(w, map[string]any{"error": "insufficient_scope"})
			return
		}
		writeJSON(w, map[string]any{"unchanged": false, "roles_declared": 1, "permissions_declared": 1})
	})

	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeInstance) signIDToken(t *testing.T, overrides map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss":   f.server.URL,
		"aud":   clientID,
		"sub":   "user-1",
		"nonce": f.nonce,
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signed, err := f.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return compact
}

func (f *fakeInstance) client(t *testing.T) *cboxid.Client {
	t.Helper()
	client, err := cboxid.New(context.Background(), cboxid.Config{
		Issuer:       f.server.URL,
		ClientID:     clientID,
		ClientSecret: "secret-xyz",
		RedirectURI:  "https://app.test/auth/callback",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

var stored = cboxid.Stored{State: "state-1", CodeVerifier: "verifier-verifier-verifier-1234567890", Nonce: "test-nonce"}

func TestCreateAuthorizationRequest(t *testing.T) {
	fake := newFakeInstance(t)
	req := fake.client(t).CreateAuthorizationRequest(cboxid.AuthParams{})

	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("client_id") != clientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("state") != req.State || q.Get("nonce") != req.Nonce {
		t.Errorf("state/nonce not reflected in URL")
	}
	if req.CodeVerifier == "" || q.Get("code_challenge") == "" {
		t.Errorf("missing PKCE verifier/challenge")
	}
}

func TestAuthenticateReturnsVerifiedUser(t *testing.T) {
	fake := newFakeInstance(t)
	user, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.ID != "user-1" || user.Email != "ada@acme.com" || user.Name != "Ada" {
		t.Errorf("unexpected user: %+v", user)
	}
	if user.OrganizationID != "org-1" {
		t.Errorf("org = %q", user.OrganizationID)
	}
	if user.AccessToken != "access-abc" {
		t.Errorf("access token = %q", user.AccessToken)
	}
}

func TestAuthenticateRejectsMismatchedState(t *testing.T) {
	fake := newFakeInstance(t)
	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "forged"}, stored)
	if !errors.Is(err, cboxid.ErrInvalidState) {
		t.Fatalf("want ErrInvalidState, got %v", err)
	}
}

func TestAuthenticateSurfacesProviderError(t *testing.T) {
	fake := newFakeInstance(t)
	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{State: "state-1", Error: "access_denied"}, stored)
	if !errors.Is(err, cboxid.ErrAuthentication) || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("want auth error mentioning access_denied, got %v", err)
	}
}

func TestAuthenticateRejectsReplayedNonce(t *testing.T) {
	fake := newFakeInstance(t)
	fake.idTokenClaims = map[string]any{"nonce": "a-different-nonce"}
	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if !errors.Is(err, cboxid.ErrAuthentication) || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("want nonce error, got %v", err)
	}
}

func TestAuthenticateRejectsWrongAudience(t *testing.T) {
	fake := newFakeInstance(t)
	fake.idTokenClaims = map[string]any{"aud": "someone-else"}
	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("want auth error, got %v", err)
	}
}

func TestDeviceAuthorizationFlow(t *testing.T) {
	fake := newFakeInstance(t)
	// The device flow has no nonce; the default id_token carries one, so clear it
	// to reflect a real device-grant token and exercise the skip-nonce path.
	fake.idTokenClaims = map[string]any{"nonce": nil}
	client := fake.client(t)

	auth, err := client.RequestDeviceAuthorization(context.Background(), cboxid.DeviceParams{})
	if err != nil {
		t.Fatalf("request device authorization: %v", err)
	}
	if auth.UserCode != "WDJB-MJHT" {
		t.Errorf("user code = %q", auth.UserCode)
	}
	if !strings.Contains(auth.VerificationURIComplete, "user_code=WDJB-MJHT") {
		t.Errorf("verification_uri_complete = %q", auth.VerificationURIComplete)
	}

	user, err := client.PollDeviceToken(context.Background(), auth)
	if err != nil {
		t.Fatalf("poll device token: %v", err)
	}
	if user.ID != "user-1" || user.Email != "ada@acme.com" {
		t.Errorf("unexpected user: %+v", user)
	}
}

func TestMachineToken(t *testing.T) {
	fake := newFakeInstance(t)
	token, err := fake.client(t).MachineToken(context.Background(), cboxid.MachineTokenParams{Scopes: []string{"reports.read"}})
	if err != nil || token != "machine-token" {
		t.Fatalf("machine token = %q, err = %v", token, err)
	}
}

func TestIntrospect(t *testing.T) {
	fake := newFakeInstance(t)
	result, err := fake.client(t).Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if active, _ := result["active"].(bool); !active {
		t.Errorf("expected active token, got %v", result["active"])
	}
}

func TestProfileAndLogoutURLs(t *testing.T) {
	fake := newFakeInstance(t)
	client := fake.client(t)

	if got := client.ProfileURL(""); got != fake.server.URL+"/settings" {
		t.Errorf("ProfileURL = %q", got)
	}
	if got := client.ProfileURL("https://app.test/home"); !strings.Contains(got, "return_to=https%3A%2F%2Fapp.test%2Fhome") {
		t.Errorf("ProfileURL with returnTo = %q", got)
	}
	if got := client.LogoutURL("https://app.test"); !strings.HasPrefix(got, fake.server.URL+"/logout") {
		t.Errorf("LogoutURL = %q", got)
	}
}
