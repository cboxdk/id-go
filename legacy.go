package cboxid

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// LegacyUser is a person as your old system knows them, on the way into Cbox ID.
//
// Everything but Email is optional, because a store that can only answer "yes, and here
// is the address" is still enough to migrate somebody.
type LegacyUser struct {
	Email         string
	Name          string
	EmailVerified bool

	// PasswordHash is your stored hash, when you can expose it.
	//
	// Passing it lets the person keep their password in Cbox ID verbatim — stored as is,
	// and upgraded to the platform hasher on their next login, exactly like a
	// bulk-imported user. Leave it empty and Cbox ID hashes the password they just proved
	// they know, which is the honest option when your store cannot hand one over.
	PasswordHash string
}

// LegacyVerifier decides whether an email and password are good, and says who they belong
// to. Return (nil, nil) for "wrong password".
//
// RETURNING AN ERROR IS DIFFERENT from returning nil: it means your store could not
// decide, and is answered with 503 so Cbox ID refuses the sign-in rather than reading an
// outage as a bad credential — and can tell the two apart in its own logs.
type LegacyVerifier func(email, password string) (*LegacyUser, error)

// ErrLegacySecretTooShort is returned when the secret cannot meaningfully sign anything.
var ErrLegacySecretTooShort = errors.New("cboxid: a legacy-login secret of at least 32 characters is required")

// LegacyLoginHandler builds the handler on YOUR side of a migration off an old login.
//
// Cbox ID offers it an email and a password it has never seen; your verifier answers with
// the person or with nothing. On a yes they are created in Cbox ID as a result of the
// login that just succeeded, and from their next sign-in the old system is never asked.
//
// WHY A CONSTRUCTOR RATHER THAN A DOCUMENTED WIRE FORMAT: the contract is a signed POST
// with JSON in and JSON out, small enough to describe in a paragraph — and describing it
// would mean every adopter writes the signature check themselves. That check is the part
// people get wrong: a plain string compare instead of a constant-time one, no freshness
// window, no thought about a captured request replayed an hour later. This owns all of it
// and reuses [VerifyWebhook], so there is one implementation of the construction in this
// package rather than two that can drift.
//
//	http.Handle("/cbox-legacy", cboxid.LegacyLoginHandler(secret, func(email, password string) (*cboxid.LegacyUser, error) {
//	    row, err := db.FindUser(email)
//	    if err != nil {
//	        return nil, err // could not decide → 503
//	    }
//	    if row == nil || !bcrypt.Match(row.Hash, password) {
//	        return nil, nil // no
//	    }
//	    return &cboxid.LegacyUser{Email: row.Email, Name: row.Name, PasswordHash: row.Hash}, nil
//	}))
func LegacyLoginHandler(secret string, verify LegacyVerifier, toleranceSeconds ...int) (http.HandlerFunc, error) {
	if len(secret) < 32 {
		// Refused here, when the handler is built, rather than at request time. A handler
		// that exists and cannot verify anything answers 500 to Cbox ID and looks like an
		// outage; failing at construction surfaces in the deploy, where somebody is looking.
		return nil, ErrLegacySecretTooShort
	}

	tolerance := 300
	if len(toleranceSeconds) > 0 && toleranceSeconds[0] > 0 {
		tolerance = toleranceSeconds[0]
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// The RAW body. The signature covers the exact bytes sent, so decoding and
		// re-encoding produces different ones and would refuse every valid request — a
		// failure that looks like a wrong secret and costs an afternoon.
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeLegacyJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})

			return
		}

		if !VerifyWebhook(string(raw), r.Header.Get("X-Cbox-Signature"), secret, tolerance) {
			// No detail. A caller who cannot sign is not owed help telling a bad signature
			// from a stale timestamp — both mean the same thing to anyone legitimate, and
			// the difference is a hint to anyone else.
			writeLegacyJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})

			return
		}

		var payload struct {
			Email    string  `json:"email"`
			Password *string `json:"password"`
		}

		if err := json.Unmarshal(raw, &payload); err != nil || payload.Email == "" {
			writeLegacyJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})

			return
		}

		// No password means Cbox ID is asking "do you know this address" — the tooling
		// path, for a dry run before cutover. It never arrives from a sign-in.
		if payload.Password == nil {
			writeLegacyJSON(w, http.StatusOK, map[string]any{"user": nil})

			return
		}

		user, err := verify(payload.Email, *payload.Password)
		if err != nil {
			// 503, not 401 — see [LegacyVerifier].
			writeLegacyJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})

			return
		}

		if user == nil {
			writeLegacyJSON(w, http.StatusOK, map[string]any{"user": nil})

			return
		}

		body := map[string]any{
			"email":          user.Email,
			"name":           user.Name,
			"email_verified": user.EmailVerified,
		}

		if user.PasswordHash != "" {
			body["password_hash"] = user.PasswordHash
		}

		writeLegacyJSON(w, http.StatusOK, body)
	}, nil
}

func writeLegacyJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
