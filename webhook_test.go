package cboxid_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"

	cboxid "github.com/cboxdk/id-go"
)

const (
	webhookSecret  = "whsec_test"
	webhookPayload = `{"event":"user.updated","id":"user-1"}`
)

// signWebhook builds a "t={ts},v1={hmac}" header exactly as Cbox ID does — an
// HMAC-SHA256 over "{ts}.{body}".
func signWebhook(t *testing.T, timestamp int64, body, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "." + body))
	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
}

func TestVerifyWebhookAcceptsFreshSignature(t *testing.T) {
	header := signWebhook(t, time.Now().Unix(), webhookPayload, webhookSecret)
	if !cboxid.VerifyWebhook(webhookPayload, header, webhookSecret, 300) {
		t.Error("a fresh, correctly-signed payload should verify")
	}
}

func TestVerifyWebhookRejectsWrongSecret(t *testing.T) {
	header := signWebhook(t, time.Now().Unix(), webhookPayload, webhookSecret)
	if cboxid.VerifyWebhook(webhookPayload, header, "whsec_other", 300) {
		t.Error("a signature made with a different secret must be rejected")
	}
}

func TestVerifyWebhookRejectsTamperedBody(t *testing.T) {
	header := signWebhook(t, time.Now().Unix(), webhookPayload, webhookSecret)
	if cboxid.VerifyWebhook(webhookPayload+"x", header, webhookSecret, 300) {
		t.Error("a body that no longer matches the signature must be rejected")
	}
}

func TestVerifyWebhookRejectsStaleTimestamp(t *testing.T) {
	// A replayed/old event outside the tolerance window must be rejected.
	header := signWebhook(t, time.Now().Unix()-10_000, webhookPayload, webhookSecret)
	if cboxid.VerifyWebhook(webhookPayload, header, webhookSecret, 300) {
		t.Error("a timestamp outside the tolerance must be rejected")
	}
}

func TestVerifyWebhookTimestampTolerance(t *testing.T) {
	// 100s old is inside a 300s tolerance…
	header := signWebhook(t, time.Now().Unix()-100, webhookPayload, webhookSecret)
	if !cboxid.VerifyWebhook(webhookPayload, header, webhookSecret, 300) {
		t.Error("a timestamp within the tolerance should verify")
	}
	// …but outside a 50s tolerance.
	if cboxid.VerifyWebhook(webhookPayload, header, webhookSecret, 50) {
		t.Error("a timestamp outside the tolerance must be rejected")
	}
}

func TestVerifyWebhookRejectsMissingOrMalformedHeader(t *testing.T) {
	cases := []string{
		"",             // missing
		"garbage",      // no key=value segments
		"t=abc,v1=xx",  // non-numeric timestamp
		"v1=deadbeef",  // no timestamp
		"t=1700000000", // no signature
	}
	for _, header := range cases {
		if cboxid.VerifyWebhook(webhookPayload, header, webhookSecret, 300) {
			t.Errorf("malformed header %q must be rejected", header)
		}
	}
}
