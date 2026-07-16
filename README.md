# cboxid — Cbox ID client for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/cboxdk/id-go.svg)](https://pkg.go.dev/github.com/cboxdk/id-go)

Turnkey [Cbox ID](https://github.com/cboxdk/laravel-id) client for Go, built for
**command-line tools**: log a CLI in with the **device authorization grant** (RFC
8628) — the flow the GitHub CLI uses — where the user approves a short code in a
browser on any device while your program polls.

It also supports the standard authorization-code + PKCE flow for server apps, plus
machine tokens, UserInfo, RFC 7662 introspection and webhook verification. The
id_token and OIDC plumbing are handled by the vetted
[`go-oidc`](https://github.com/coreos/go-oidc) and
[`x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) — no hand-rolled crypto.

## Install

```bash
go get github.com/cboxdk/id-go
```

## CLI login (device flow)

```go
client, _ := cboxid.New(ctx, cboxid.Config{
    Issuer:      "https://id.acme.com",
    ClientID:    "client_...",
    RedirectURI: "http://localhost", // unused by the device flow, but required
    Scopes:      []string{"openid", "profile", "email", "offline_access"},
})

auth, _ := client.RequestDeviceAuthorization(ctx, cboxid.DeviceParams{})
fmt.Printf("Visit %s and enter code %s\n", auth.VerificationURI, auth.UserCode)

// Blocks until the user approves (or the code expires); honors the poll interval.
user, err := client.PollDeviceToken(ctx, auth)
fmt.Printf("Signed in as %s\n", user.Email)
// Persist user.Token (with its refresh token) to your CLI config for next time.
```

A complete, runnable example is in [`examples/cli`](examples/cli).

## Server login (authorization code + PKCE)

```go
req := client.CreateAuthorizationRequest(cboxid.AuthParams{})
// persist req.State, req.CodeVerifier, req.Nonce; redirect the user to req.URL

// on the callback:
user, err := client.Authenticate(ctx,
    cboxid.Callback{Code: code, State: state},
    cboxid.Stored{State: req.State, CodeVerifier: req.CodeVerifier, Nonce: req.Nonce},
)
```

## Back-channel calls

```go
token, _ := client.MachineToken(ctx, cboxid.MachineTokenParams{Scopes: []string{"reports.read"}})
claims, _ := client.UserInfo(ctx, user.AccessToken)
result, _ := client.Introspect(ctx, someToken) // RFC 7662
```

## Verify webhooks

```go
ok := cboxid.VerifyWebhook(rawBody, r.Header.Get("X-Cbox-Signature"), webhookSecret, 300)
```

## Errors

Errors wrap the sentinels `cboxid.ErrInvalidState`, `cboxid.ErrAuthentication` and
`cboxid.ErrConfiguration` — match them with `errors.Is`. A state mismatch is
`ErrInvalidState`; treat it as a fresh start, not a user-facing error.

## Security & scope

Login is hardened by default — PKCE, `state`, nonce (auth-code flow), and full
id_token verification (signature/issuer/audience) via go-oidc. Key accounts on
`user.ID` (the stable subject), not on email.

This is a **client**. It authenticates users and calls a Cbox ID instance's standard
endpoints; it does not configure SSO, run SCIM, or manage organizations — those are
platform capabilities of [`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id).

Report vulnerabilities via this repo's GitHub **Private Vulnerability Reporting**.

## License

MIT © Cbox.
