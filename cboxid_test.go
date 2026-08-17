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
	server          *httptest.Server
	signer          jose.Signer
	nonce           string
	idTokenClaims   map[string]any // overrides for the default id_token
	idTokenOverride string         // when set, /token returns this raw id_token verbatim

	// Recorded by the /token, /revoke and /api/v1/apps/manifest handlers for assertions.
	tokenScope     string
	revokeForm     url.Values
	revokeAuthUser string
	revokeAuthPass string
	revokeCalls    int
	manifestAuth   string
	manifestBody   map[string]any
	manifestStatus int // response status for the manifest endpoint; 0 => 200

	// tokenHandler, when set, answers /token instead of the default success path — so a
	// test can assert what the SDK makes of an RFC 6749 §5.2 error body and its headers.
	tokenHandler http.HandlerFunc

	// userInfo, when set, replaces the default /userinfo body — the only way to make it
	// disagree with the signed id_token, which is what OIDC Core §5.3.2 is about.
	userInfo map[string]any
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
			"revocation_endpoint":           fake.server.URL + "/revoke",
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
		if fake.tokenHandler != nil {
			fake.tokenHandler(w, r)
			return
		}

		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "client_credentials" {
			fake.tokenScope = r.Form.Get("scope")
			writeJSON(w, map[string]any{"access_token": "machine-token", "token_type": "Bearer"})
			return
		}
		idToken := fake.idTokenOverride
		if idToken == "" {
			idToken = fake.signIDToken(t, fake.idTokenClaims)
		}
		writeJSON(w, map[string]any{
			"access_token":  "access-abc",
			"refresh_token": "refresh-abc",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"id_token":      idToken,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		if fake.userInfo != nil {
			writeJSON(w, fake.userInfo)
			return
		}
		writeJSON(w, map[string]any{"sub": "user-1", "email": "ada@acme.com", "name": "Ada", "org": "org-1"})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"active": true, "sub": "user-1", "scope": "openid"})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fake.revokeCalls++
		fake.revokeForm = r.Form
		fake.revokeAuthUser, fake.revokeAuthPass, _ = r.BasicAuth()
		// RFC 7009: a successful revocation carries an empty 200 body.
		w.WriteHeader(http.StatusOK)
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

func TestRefresh(t *testing.T) {
	fake := newFakeInstance(t)
	client := fake.client(t)

	token, err := client.Refresh(context.Background(), "refresh-abc")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if token.AccessToken != "access-abc" {
		t.Errorf("AccessToken = %q, want access-abc", token.AccessToken)
	}
	if token.RefreshToken != "refresh-abc" {
		t.Errorf("RefreshToken = %q, want refresh-abc", token.RefreshToken)
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

func TestRevoke(t *testing.T) {
	fake := newFakeInstance(t)
	if err := fake.client(t).Revoke(context.Background(), "refresh-abc", cboxid.HintRefreshToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if fake.revokeCalls != 1 {
		t.Fatalf("revoke calls = %d, want 1", fake.revokeCalls)
	}
	if got := fake.revokeForm.Get("token"); got != "refresh-abc" {
		t.Errorf("token = %q", got)
	}
	if got := fake.revokeForm.Get("token_type_hint"); got != "refresh_token" {
		t.Errorf("token_type_hint = %q", got)
	}
	if fake.revokeAuthUser != clientID || fake.revokeAuthPass != "secret-xyz" {
		t.Errorf("basic auth = %q:%q", fake.revokeAuthUser, fake.revokeAuthPass)
	}
}

func TestRevokeOmitsAnEmptyHint(t *testing.T) {
	fake := newFakeInstance(t)
	if err := fake.client(t).Revoke(context.Background(), "access-abc", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := fake.revokeForm["token_type_hint"]; ok {
		t.Errorf("token_type_hint was sent for an empty hint")
	}
}

// The clients that most need revocation were the ones that could not call it.
//
// A PKCE native or CLI app authenticates with "none" and holds no secret — and it is
// exactly the case where a refresh token sits on a device somebody has just signed out
// of. Revoke refused before reaching the network, so every such sign-out left the token
// valid for its whole lifetime.
//
// The server opened this on 2026-08-12 and advertises "none" among its revocation auth
// methods. The assertion this replaces described the world before that. RFC 7009 §2.1
// scopes a revocation to the calling client, so the only capability is destroying a token
// you already hold.
func TestRevokeWorksForAPublicClient(t *testing.T) {
	fake := newFakeInstance(t)
	client, err := cboxid.New(context.Background(), cboxid.Config{
		Issuer:      fake.server.URL,
		ClientID:    clientID,
		RedirectURI: "https://app.test/auth/callback",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.Revoke(context.Background(), "some-token", ""); err != nil {
		t.Fatalf("public-client revoke: %v", err)
	}
	if fake.revokeCalls != 1 {
		t.Fatalf("revocation calls = %d, want 1", fake.revokeCalls)
	}
	if got := fake.revokeForm.Get("client_id"); got != clientID {
		t.Errorf("client_id in body = %q, want %q", got, clientID)
	}
	// No secret to build one from, and an empty Basic header would authenticate as a
	// confidential client with a blank password — which the server must refuse.
	if fake.revokeAuthUser != "" || fake.revokeAuthPass != "" {
		t.Errorf("a public client sent Basic auth: %q / %q", fake.revokeAuthUser, fake.revokeAuthPass)
	}
}

func TestProfileAndLogoutURLs(t *testing.T) {
	fake := newFakeInstance(t)
	client := fake.client(t)

	// "/account", not "/settings": the latter is the organization-admin page, which
	// redirects a non-admin to "/account" and drops return_to on the way — so the link
	// worked for admins and silently lost the return path for everyone else.
	if got := client.ProfileURL(""); got != fake.server.URL+"/account" {
		t.Errorf("ProfileURL = %q", got)
	}
	if got := client.ProfileURL("https://app.test/home"); !strings.Contains(got, "return_to=https%3A%2F%2Fapp.test%2Fhome") {
		t.Errorf("ProfileURL with returnTo = %q", got)
	}
	// The OP validates post_logout_redirect_uri against the requesting client's
	// registered allow-list, so a logout URL without client_id can never redirect —
	// it strands the user on a bare "signed out" page.
	got := client.LogoutURL("https://app.test")
	if !strings.HasPrefix(got, fake.server.URL+"/logout") {
		t.Fatalf("LogoutURL = %q", got)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("LogoutURL is not a URL: %v", err)
	}
	if q := parsed.Query(); q.Get("client_id") != clientID {
		t.Errorf("LogoutURL client_id = %q, want %q", q.Get("client_id"), clientID)
	} else if q.Get("post_logout_redirect_uri") != "https://app.test" {
		t.Errorf("LogoutURL post_logout_redirect_uri = %q", q.Get("post_logout_redirect_uri"))
	} else if q.Get("id_token_hint") != "" {
		t.Errorf("LogoutURL carried an unasked-for id_token_hint %q", q.Get("id_token_hint"))
	}

	if q := mustQuery(t, client.LogoutURL("")); q.Get("client_id") != clientID {
		t.Errorf("bare LogoutURL dropped client_id: %v", q)
	} else if q.Has("post_logout_redirect_uri") {
		t.Errorf("bare LogoutURL invented a redirect: %v", q)
	}

	if q := mustQuery(t, client.LogoutURLWithHint("https://app.test", "header.payload.sig")); q.Get("id_token_hint") != "header.payload.sig" {
		t.Errorf("LogoutURLWithHint id_token_hint = %q", q.Get("id_token_hint"))
	} else if q.Get("client_id") != clientID {
		t.Errorf("LogoutURLWithHint dropped client_id: %v", q)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("not a URL: %v", err)
	}
	return parsed.Query()
}

// TestRefreshCarriesTheOAuthErrorAndRetryAfter proves the server's own answer survives.
//
// x/oauth2 already parses the RFC 6749 §5.2 body; this package was flattening all of it
// into %v, so a caller had one prose string for outcomes that demand opposite responses.
// invalid_grant means the session is over and the person must sign in again; a 429 means
// the same request succeeds unchanged if you wait, and the server says how long.
func TestRefreshCarriesTheOAuthErrorAndRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		header      string
		wantCode    string
		wantRetry   int
		wantLimited bool
	}{
		{
			name:     "invalid_grant",
			status:   http.StatusBadRequest,
			body:     `{"error":"invalid_grant","error_description":"Refresh token was revoked."}`,
			wantCode: "invalid_grant",
		},
		{
			name:        "rate limited with seconds",
			status:      http.StatusTooManyRequests,
			body:        `{"error":"temporarily_unavailable"}`,
			header:      "42",
			wantCode:    "temporarily_unavailable",
			wantRetry:   42,
			wantLimited: true,
		},
		{
			// Legal per RFC 9110 and deliberately not parsed: guessing at clock skew is
			// worse than saying nothing, and RateLimited() still says back off.
			name:        "rate limited with an HTTP-date",
			status:      http.StatusTooManyRequests,
			body:        `{"error":"temporarily_unavailable"}`,
			header:      "Wed, 21 Oct 2026 07:28:00 GMT",
			wantCode:    "temporarily_unavailable",
			wantRetry:   0,
			wantLimited: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeInstance(t)
			fake.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
				if tc.header != "" {
					w.Header().Set("Retry-After", tc.header)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}

			client := fake.client(t)

			_, err := client.Refresh(context.Background(), "spent-token")
			if err == nil {
				t.Fatal("want an error")
			}

			// The sentinel still matches — existing callers are untouched.
			if !errors.Is(err, cboxid.ErrAuthentication) {
				t.Errorf("errors.Is(ErrAuthentication) = false, want true")
			}

			var oauthErr *cboxid.OAuthError
			if !errors.As(err, &oauthErr) {
				t.Fatalf("errors.As(*OAuthError) = false for %v", err)
			}

			if oauthErr.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", oauthErr.Code, tc.wantCode)
			}
			if oauthErr.RetryAfter != tc.wantRetry {
				t.Errorf("RetryAfter = %d, want %d", oauthErr.RetryAfter, tc.wantRetry)
			}
			if oauthErr.RateLimited() != tc.wantLimited {
				t.Errorf("RateLimited() = %v, want %v", oauthErr.RateLimited(), tc.wantLimited)
			}
		})
	}
}

// TestUserInfoIsBoundToTheVerifiedIDToken holds OIDC Core §5.3.2.
//
// UserInfo is fetched with a bearer token and its body carries no signature. Both maps
// used to be decoded into ONE, id_token first and UserInfo second, so whatever UserInfo
// returned won — including sub and org. The sibling PHP SDK had checked this from the
// start, so the two SDKs disagreed about who the user is.
func TestUserInfoIsBoundToTheVerifiedIDToken(t *testing.T) {
	t.Run("refuses a different subject", func(t *testing.T) {
		fake := newFakeInstance(t)
		// The whole attack in one line: the signed token says user-1, the unsigned body
		// says somebody else.
		fake.userInfo = map[string]any{"sub": "victim-9", "email": "victim@acme.com"}
		client := fake.client(t)

		_, err := client.Authenticate(context.Background(),
			cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)

		if err == nil {
			t.Fatal("a UserInfo response naming another subject was accepted")
		}
		if !strings.Contains(err.Error(), "UserInfo subject") {
			t.Errorf("error = %v, want the subject-mismatch refusal", err)
		}
	})

	t.Run("enriches but never overrides a signed claim", func(t *testing.T) {
		fake := newFakeInstance(t)
		// org is an authorization claim: whoever sets it decides which tenant this is.
		// It has to be IN the id_token for the precedence to be observable at all — the
		// default fixture omits it, so UserInfo was legitimately filling a gap rather
		// than overriding anything, and my first version of this test asserted against
		// behaviour that was already correct.
		fake.idTokenClaims = map[string]any{"org": "org-1"}
		fake.userInfo = map[string]any{
			"sub": "user-1", "email": "ada@acme.com", "name": "Ada",
			"org": "org-admin", "title": "Engineer",
		}
		client := fake.client(t)

		user, err := client.Authenticate(context.Background(),
			cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}

		if user.OrganizationID != "org-1" {
			t.Errorf("OrganizationID = %q, want the SIGNED org-1", user.OrganizationID)
		}
		// …and the enrichment still happens, which is why the merge exists at all.
		if got, _ := user.Claims["title"].(string); got != "Engineer" {
			t.Errorf("title = %q, want the UserInfo enrichment to survive", got)
		}
	})
}
