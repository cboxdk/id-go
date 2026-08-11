package cboxid_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cboxid "github.com/cboxdk/id-go"
)

const legacySecret = "a-secret-long-enough-to-mean-something-here"

func sign(body, secret string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", timestamp, body)))

	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
}

func post(t *testing.T, handler http.HandlerFunc, body, signature string) (int, map[string]any) {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/cbox-legacy", strings.NewReader(body))
	if signature != "" {
		request.Header.Set("X-Cbox-Signature", signature)
	}

	recorder := httptest.NewRecorder()
	handler(recorder, request)

	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)

	return recorder.Code, decoded
}

func ada(string, string) (*cboxid.LegacyUser, error) {
	return &cboxid.LegacyUser{Email: "ada@acme.test", Name: "Ada", EmailVerified: true}, nil
}

// A handler that exists and cannot verify anything answers 500 to Cbox ID and looks like
// an outage. Failing at construction surfaces in the deploy, where somebody is looking.
func TestRefusesASecretTooShortToMeanAnything(t *testing.T) {
	if _, err := cboxid.LegacyLoginHandler("short", ada); !errors.Is(err, cboxid.ErrLegacySecretTooShort) {
		t.Fatalf("expected ErrLegacySecretTooShort, got %v", err)
	}
}

func TestAnswersWithThePersonWhenCredentialsAreGood(t *testing.T) {
	handler, err := cboxid.LegacyLoginHandler(legacySecret, ada)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"email":"ada@acme.test","password":"pw"}`
	status, decoded := post(t, handler, body, sign(body, legacySecret, time.Now().Unix()))

	if status != http.StatusOK || decoded["email"] != "ada@acme.test" {
		t.Fatalf("got %d %v", status, decoded)
	}
}

// The check this constructor exists to own — the part adopters would otherwise write, and
// the part people get wrong.
func TestRefusesUnsignedWrongAndStaleWithoutConsultingTheStore(t *testing.T) {
	called := false
	handler, err := cboxid.LegacyLoginHandler(legacySecret, func(string, string) (*cboxid.LegacyUser, error) {
		called = true

		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"email":"ada@acme.test","password":"pw"}`

	cases := map[string]string{
		"unsigned":     "",
		"wrong secret": sign(body, "a-different-secret-of-adequate-length!", time.Now().Unix()),
		"stale":        sign(body, legacySecret, time.Now().Unix()-400),
	}

	for name, signature := range cases {
		if status, _ := post(t, handler, body, signature); status != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", name, status)
		}
	}

	if called {
		t.Fatal("the store was consulted for a request that could not be verified")
	}
}

// The signature covers the RAW bytes; decoding and re-encoding produces different ones and
// would refuse every valid request.
func TestVerifiesTheExactBytesItWasSent(t *testing.T) {
	handler, _ := cboxid.LegacyLoginHandler(legacySecret, ada)

	body := `{"email":"ada@acme.test",  "password":"pw"}`

	if status, _ := post(t, handler, body, sign(body, legacySecret, time.Now().Unix())); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
}

// A returned error means the store could not DECIDE, which is not a wrong password — and
// Cbox ID needs to tell the two apart in its own logs.
func TestAnswers503WhenTheStoreCannotDecide(t *testing.T) {
	handler, _ := cboxid.LegacyLoginHandler(legacySecret, func(string, string) (*cboxid.LegacyUser, error) {
		return nil, errors.New("database is down")
	})

	body := `{"email":"ada@acme.test","password":"pw"}`

	if status, _ := post(t, handler, body, sign(body, legacySecret, time.Now().Unix())); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", status)
	}
}

func TestSaysNoPlainlyForAWrongPassword(t *testing.T) {
	handler, _ := cboxid.LegacyLoginHandler(legacySecret, func(string, string) (*cboxid.LegacyUser, error) {
		return nil, nil
	})

	body := `{"email":"ada@acme.test","password":"wrong"}`
	status, decoded := post(t, handler, body, sign(body, legacySecret, time.Now().Unix()))

	if status != http.StatusOK || decoded["user"] != nil {
		t.Fatalf("got %d %v", status, decoded)
	}
}

func TestAnswersAPasswordlessProbeWithoutConsultingTheStore(t *testing.T) {
	called := false
	handler, _ := cboxid.LegacyLoginHandler(legacySecret, func(string, string) (*cboxid.LegacyUser, error) {
		called = true

		return nil, nil
	})

	body := `{"email":"ada@acme.test"}`
	status, _ := post(t, handler, body, sign(body, legacySecret, time.Now().Unix()))

	if status != http.StatusOK || called {
		t.Fatalf("status %d, store consulted: %v", status, called)
	}
}

func TestPassesAStoredHashThrough(t *testing.T) {
	handler, _ := cboxid.LegacyLoginHandler(legacySecret, func(string, string) (*cboxid.LegacyUser, error) {
		return &cboxid.LegacyUser{Email: "ada@acme.test", PasswordHash: "$2y$10$abc"}, nil
	})

	body := `{"email":"ada@acme.test","password":"pw"}`
	_, decoded := post(t, handler, body, sign(body, legacySecret, time.Now().Unix()))

	if decoded["password_hash"] != "$2y$10$abc" {
		t.Fatalf("hash not carried: %v", decoded)
	}
}
