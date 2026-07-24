package cboxid_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	cboxid "github.com/cboxdk/id-go"
)

// foreignIDToken signs the default id_token claims with a keypair the JWKS does NOT
// advertise, but still presents kid "test-key" — so the verifier selects the real
// key and the signature check must fail.
func foreignIDToken(t *testing.T, fake *fakeInstance) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "test-key"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new foreign signer: %v", err)
	}
	claims := map[string]any{
		"iss":   fake.server.URL,
		"aud":   clientID,
		"sub":   "user-1",
		"nonce": fake.nonce,
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal foreign claims: %v", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign foreign token: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize foreign token: %v", err)
	}
	return compact
}

// tamperClaim decodes a compact JWT's payload, rewrites one claim, and re-attaches the
// ORIGINAL signature — a forgery the verifier must reject.
func tamperClaim(t *testing.T, token, claim string, value any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-part JWT, got %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	claims[claim] = value
	repacked, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(repacked)
	return strings.Join(parts, ".")
}

func TestAuthenticateRejectsForeignKeySignature(t *testing.T) {
	fake := newFakeInstance(t)
	fake.idTokenOverride = foreignIDToken(t, fake)

	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("want ErrAuthentication for a foreign-key signature, got %v", err)
	}
}

func TestAuthenticateRejectsTamperedPayload(t *testing.T) {
	fake := newFakeInstance(t)
	valid := fake.signIDToken(t, nil)
	fake.idTokenOverride = tamperClaim(t, valid, "sub", "attacker")

	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("want ErrAuthentication for a tampered payload, got %v", err)
	}
}

func TestAuthenticateRejectsExpiredToken(t *testing.T) {
	fake := newFakeInstance(t)
	fake.idTokenClaims = map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}

	_, err := fake.client(t).Authenticate(context.Background(),
		cboxid.Callback{Code: "auth-code", State: "state-1"}, stored)
	if !errors.Is(err, cboxid.ErrAuthentication) {
		t.Fatalf("want ErrAuthentication for an expired token, got %v", err)
	}
}
