package cboxid_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

func frontendServer(t *testing.T, status int, body any, seen *[]*http.Request) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = append(*seen, r.Clone(r.Context()))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

// Putting a client secret where a public key belongs is the mistake this channel exists to
// make unnecessary; as an opaque 401 in a log the cause would be invisible.
func TestRefusesAnythingThatIsNotAPublishableKey(t *testing.T) {
	if _, err := cboxid.NewFrontendClient("https://id.acme.test", "sk_live_secret", nil); err != cboxid.ErrNotPublishableKey {
		t.Fatalf("expected ErrNotPublishableKey, got %v", err)
	}
}

func TestSendsTheKeyInAHeaderNeverAQueryString(t *testing.T) {
	var seen []*http.Request
	server := frontendServer(t, 200, map[string]any{"issuer": "https://id.acme.test", "endpoints": map[string]string{}}, &seen)
	defer server.Close()

	client, _ := cboxid.NewFrontendClient(server.URL, "pk_live_abc", server.Client())

	if _, err := client.Config(context.Background()); err != nil {
		t.Fatal(err)
	}

	if seen[0].Header.Get("X-Cbox-Publishable-Key") != "pk_live_abc" {
		t.Fatal("key not sent as a header")
	}

	if seen[0].URL.RawQuery != "" {
		t.Fatal("key or anything else leaked into the query string")
	}
}

func TestFetchesTheDocumentOncePerClient(t *testing.T) {
	var seen []*http.Request
	server := frontendServer(t, 200, map[string]any{"issuer": "x", "endpoints": map[string]string{}}, &seen)
	defer server.Close()

	client, _ := cboxid.NewFrontendClient(server.URL, "pk_live_abc", server.Client())

	_, _ = client.Config(context.Background())
	_, _ = client.Config(context.Background())

	if len(seen) != 1 {
		t.Fatalf("expected one fetch, got %d", len(seen))
	}
}

// Signed-out is a state, not an error: code that renders an avatar on every page should
// not have to treat a rejection as one.
func TestAnEmptyTokenIsAnEmptySessionAndNoCallAtAll(t *testing.T) {
	var seen []*http.Request
	server := frontendServer(t, 200, map[string]any{}, &seen)
	defer server.Close()

	client, _ := cboxid.NewFrontendClient(server.URL, "pk_live_abc", server.Client())

	session, err := client.Session(context.Background(), "")
	if err != nil || session.User != nil {
		t.Fatalf("got %v %v", session, err)
	}

	if len(seen) != 0 {
		t.Fatal("called out for a caller with no token")
	}
}

func TestNamesTheAllowListWhenRefused(t *testing.T) {
	server := frontendServer(t, 401, map[string]any{"error": "unauthorized"}, nil)
	defer server.Close()

	client, _ := cboxid.NewFrontendClient(server.URL, "pk_live_abc", server.Client())

	_, err := client.Config(context.Background())
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("expected the allow-list named, got %v", err)
	}
}

func TestKnowsWhetherItDrivesRealSignIns(t *testing.T) {
	live, _ := cboxid.NewFrontendClient("https://id.acme.test", "pk_live_a", nil)
	test, _ := cboxid.NewFrontendClient("https://id.acme.test", "pk_test_a", nil)

	if !live.IsLive() || test.IsLive() {
		t.Fatal("mode not read from the key")
	}
}

// A blip must not poison the client for the life of the process.
//
// `sync.Once` cached the FAILURE too: one network hiccup — or a first caller whose context
// was already cancelled — and a server that draws a sign-in box on every page never drew
// one again until somebody restarted it.
func TestConfigRecoversAfterAFailure(t *testing.T) {
	t.Parallel()

	var calls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++

		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://id.acme.test","endpoints":{}}`))
	}))
	defer server.Close()

	client, err := cboxid.NewFrontendClient(server.URL, "pk_test_abc", server.Client())
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}

	if _, err := client.Config(context.Background()); err == nil {
		t.Fatal("expected the first call to fail")
	}

	config, err := client.Config(context.Background())
	if err != nil {
		t.Fatalf("the client did not recover: %v", err)
	}

	if config.Issuer != "https://id.acme.test" {
		t.Fatalf("unexpected issuer %q", config.Issuer)
	}
}

// A refusal is the one failure a caller can act on, so it has to be distinguishable from
// an outage without matching on prose — and it must carry the server's own reason.
func TestARefusalIsTypedAndKeepsTheServersReason(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing_key","error_description":"No publishable key was presented."}`))
	}))
	defer server.Close()

	client, _ := cboxid.NewFrontendClient(server.URL, "pk_test_abc", server.Client())

	_, err := client.Config(context.Background())

	if !errors.Is(err, cboxid.ErrUnauthorized) {
		t.Fatalf("expected cboxid.ErrUnauthorized, got %v", err)
	}

	if !strings.Contains(err.Error(), "No publishable key was presented") {
		t.Fatalf("the server's own reason was discarded: %v", err)
	}
}

// The key travels in a custom header and the session call carries a bearer token. Go
// strips Authorization across domains but never across ports, and never strips a custom
// header at all, so a redirect would hand both to whoever the Location names.
func TestTheFrontendClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var reachedElsewhere bool

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedElsewhere = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://evil.test","endpoints":{}}`))
	}))
	defer elsewhere.Close()

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/frontend/v1/config", http.StatusFound)
	}))
	defer issuer.Close()

	client, _ := cboxid.NewFrontendClient(issuer.URL, "pk_test_abc", nil)

	if _, err := client.Config(context.Background()); err == nil {
		t.Fatal("expected the redirect to be refused")
	}

	if reachedElsewhere {
		t.Fatal("the publishable key was handed to the redirect target")
	}
}
