package cboxid_test

import (
	"context"
	"testing"

	cboxid "github.com/cboxdk/id-go"
)

// A CLI has no callback URL — that is the entire reason RFC 8628 exists. Requiring one
// to construct a client meant every CLI carried `RedirectURI: "http://localhost", //
// unused by the device flow, but required`: a value that means nothing, sitting where a
// security-relevant one usually sits, in the file the next person copies from.
func TestNewDeviceClientNeedsNoRedirectURI(t *testing.T) {
	fake := newFakeInstance(t)

	client, err := cboxid.NewDeviceClient(context.Background(), cboxid.DeviceConfig{
		Issuer:   fake.server.URL,
		ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("a device client must construct without a redirect URI: %v", err)
	}
	if client == nil {
		t.Fatal("expected a client")
	}
}

// And the browser flow still refuses to start without one, where the absence matters.
// An authorize URL missing redirect_uri fails at the authorization server instead,
// describing a request the caller never knowingly made.
func TestAuthorizationRequestStillRequiresRedirectURI(t *testing.T) {
	fake := newFakeInstance(t)

	client, err := cboxid.NewDeviceClient(context.Background(), cboxid.DeviceConfig{
		Issuer:   fake.server.URL,
		ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("the browser flow must refuse a client that has no redirect URI")
		}
	}()

	client.CreateAuthorizationRequest(cboxid.AuthParams{})
}
