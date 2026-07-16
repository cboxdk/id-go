package cboxid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// VerifyWebhook verifies a Cbox ID webhook / inline-action signature. The header is
// "t={unix},v1={hex hmac}" — an HMAC-SHA256 over "{timestamp}.{raw body}", valid
// within toleranceSeconds. Pass the RAW request body, not a re-serialized copy. It
// returns false (never panics) on any problem.
func VerifyWebhook(payload string, signatureHeader string, secret string, toleranceSeconds int) bool {
	if signatureHeader == "" {
		return false
	}

	var timestamp, signature string
	for _, segment := range strings.Split(signatureHeader, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(segment), "=")
		if !found {
			continue
		}
		switch key {
		case "t":
			timestamp = value
		case "v1":
			signature = value
		}
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || signature == "" {
		return false
	}

	if toleranceSeconds <= 0 {
		toleranceSeconds = 300
	}
	if delta := time.Now().Unix() - ts; delta > int64(toleranceSeconds) || delta < -int64(toleranceSeconds) {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}
