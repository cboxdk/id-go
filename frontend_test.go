package cboxid_test

import (
	"context"
	"encoding/json"
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
