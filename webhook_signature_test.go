package cboxid_test

// Golden webhook-signature vectors, shared byte-for-byte with laravel-id (the
// sender) and with id-js, id-python and laravel-id-client.
//
// webhook_test.go signs with its own copy of the formula and then verifies it, so it
// stays green even when this SDK and the server disagree: flip the signed string
// from "{timestamp}.{body}" to "{body}.{timestamp}" on either side and that suite
// still passes while every delivery fails in the field. The signatures below are
// fixed bytes produced by the server implementation and independently reproduced
// with OpenSSL and Python.

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cboxid "github.com/cboxdk/id-go"
)

type webhookSignatureCase struct {
	Name                   string `json:"name"`
	Secret                 string `json:"secret"`
	Timestamp              int64  `json:"timestamp"`
	Body                   string `json:"body"`
	SignedPayload          string `json:"signed_payload"`
	Signature              string `json:"signature"`
	Header                 string `json:"header"`
	ReversedOrderSignature string `json:"reversed_order_signature"`
	ReversedOrderHeader    string `json:"reversed_order_header"`
}

func loadWebhookSignatureFixture(t *testing.T) []webhookSignatureCase {
	t.Helper()

	data, err := os.ReadFile("testdata/webhook_signature.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var fixture struct {
		Cases []webhookSignatureCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture had no cases")
	}

	return fixture.Cases
}

// toleranceFor widens the freshness window enough to cover the fixture's fixed
// timestamp. VerifyWebhook reads the wall clock, and these vectors are deliberately
// pinned in the past; freshness itself is covered by webhook_test.go.
func toleranceFor(timestamp int64) int {
	delta := time.Now().Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	return int(delta) + 300
}

func TestVerifyWebhookAcceptsSharedGoldenVectors(t *testing.T) {
	for _, c := range loadWebhookSignatureFixture(t) {
		t.Run(c.Name, func(t *testing.T) {
			if !cboxid.VerifyWebhook(c.Body, c.Header, c.Secret, toleranceFor(c.Timestamp)) {
				t.Errorf("the golden signature from the shared fixture must verify\n header: %s", c.Header)
			}
		})
	}
}

func TestVerifyWebhookRejectsReversedConcatenation(t *testing.T) {
	for _, c := range loadWebhookSignatureFixture(t) {
		t.Run(c.Name, func(t *testing.T) {
			// The same secret, timestamp and body signed as "{body}.{timestamp}".
			// A verifier that concatenates the other way round accepts this — and
			// rejects every real delivery.
			if cboxid.VerifyWebhook(c.Body, c.ReversedOrderHeader, c.Secret, toleranceFor(c.Timestamp)) {
				t.Error("a signature over the reversed concatenation must be rejected")
			}
		})
	}
}

func TestVerifyWebhookRejectsGoldenSignatureOverTamperedBody(t *testing.T) {
	for _, c := range loadWebhookSignatureFixture(t) {
		t.Run(c.Name, func(t *testing.T) {
			if cboxid.VerifyWebhook(c.Body+" ", c.Header, c.Secret, toleranceFor(c.Timestamp)) {
				t.Error("a golden signature must not verify against a modified body")
			}
		})
	}
}

func TestVerifyWebhookVerifiesRawBytesNotAReserializedBody(t *testing.T) {
	// The unicode case ships escaped slashes and \uXXXX escapes. Re-encoding the
	// parsed document yields equivalent JSON with different bytes, which must NOT
	// verify — the most common webhook integration bug.
	for _, c := range loadWebhookSignatureFixture(t) {
		if c.Name != "unicode_and_escaped_slashes" {
			continue
		}

		var parsed any
		if err := json.Unmarshal([]byte(c.Body), &parsed); err != nil {
			t.Fatalf("parse case body: %v", err)
		}
		reSerialized, err := json.Marshal(parsed)
		if err != nil {
			t.Fatalf("re-serialize case body: %v", err)
		}
		if string(reSerialized) == c.Body {
			t.Fatal("expected re-serialization to change the bytes")
		}

		if cboxid.VerifyWebhook(string(reSerialized), c.Header, c.Secret, toleranceFor(c.Timestamp)) {
			t.Error("a re-serialized body must not verify against the raw-bytes signature")
		}

		return
	}

	t.Fatal("fixture is missing the unicode_and_escaped_slashes case")
}

// loadWebhookSignatureDocument returns the fixture's templates alongside its cases.
// The templates are what every SDK builds its expectation from, and were the one field
// no test in any of them read.
func loadWebhookSignatureDocument(t *testing.T) (string, string, []webhookSignatureCase) {
	t.Helper()

	data, err := os.ReadFile("testdata/webhook_signature.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var fixture struct {
		SignedPayloadTemplate string                 `json:"signed_payload_template"`
		HeaderTemplate        string                 `json:"header_template"`
		Cases                 []webhookSignatureCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	return fixture.SignedPayloadTemplate, fixture.HeaderTemplate, fixture.Cases
}

// TestFixturePinsTheSignedPayloadOrder states the wire format once, as a constant.
//
// This package verifies against its OWN copy of the fixture, as every SDK does, so a
// copy that drifts is silent: this suite stays green against the drifted bytes while
// every delivery from the server fails in the field. Deliberately NOT derived from the
// file it guards — "{timestamp}.{body}" is the contract with the sender, and a copy
// that says otherwise is wrong rather than authoritative.
func TestFixturePinsTheSignedPayloadOrder(t *testing.T) {
	signedPayload, header, _ := loadWebhookSignatureDocument(t)

	if signedPayload != "{timestamp}.{body}" {
		t.Errorf("signed_payload_template = %q, want %q", signedPayload, "{timestamp}.{body}")
	}
	if header != "t={timestamp},v1={signature}" {
		t.Errorf("header_template = %q, want %q", header, "t={timestamp},v1={signature}")
	}
}

// TestFixtureCasesMatchTheirTemplates proves the templates and the per-case literals are
// the same fact stated twice, so either edited alone fails. The vector tests hash the
// literal, so a flipped template alone used to change nothing.
func TestFixtureCasesMatchTheirTemplates(t *testing.T) {
	template, _, cases := loadWebhookSignatureDocument(t)

	if len(cases) == 0 {
		t.Fatal("fixture had no cases")
	}

	for _, c := range cases {
		want := strings.ReplaceAll(template, "{timestamp}", strconv.FormatInt(c.Timestamp, 10))
		want = strings.ReplaceAll(want, "{body}", c.Body)

		if want != c.SignedPayload {
			t.Errorf("%s: template built %q, fixture published %q", c.Name, want, c.SignedPayload)
		}
	}
}
