# cboxid — Cbox ID client for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/cboxdk/id-go.svg)](https://pkg.go.dev/github.com/cboxdk/id-go)

Turnkey [Cbox ID](https://github.com/cboxdk/laravel-id) client for Go, built for
**command-line tools**: log a CLI in with the **device authorization grant** (RFC
8628) — the flow the GitHub CLI uses — where the user approves a short code in a
browser on any device while your program polls.

It also supports the standard authorization-code + PKCE flow for server apps, plus
machine tokens, UserInfo, RFC 7662 introspection, RFC 7009 revocation and webhook
verification. The id_token and OIDC plumbing are handled by the vetted
[`go-oidc`](https://github.com/coreos/go-oidc) and
[`x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) — no hand-rolled crypto.

## In a browser-facing service (publishable keys)

Everything else here assumes a confidential client. A **publishable key** is the opposite —
public on purpose, useful only from the origins you registered. Reading the environment's
own sign-in configuration lets a Go template render a themed sign-in box without shipping a
JavaScript SDK to do it:

```go
frontend, err := cboxid.NewFrontendClient("https://id.acme.com", "pk_live_…", nil)
config, err := frontend.Config(ctx)          // endpoints, social buttons, the theme
session, err := frontend.Session(ctx, token) // session.User is nil when nobody is signed in
```

An empty token yields an empty session rather than an error, and the key grants nothing on
its own: the access token is the entire authority. A client secret passed there returns
`ErrNotPublishableKey` at construction.

## Migrating off an old login

Cbox ID can ask your service whether an email and password it has never seen are good, and
import that person on the yes. You write the lookup; the handler owns the signature, the
freshness window and the constant-time compare:

```go
handler, err := cboxid.LegacyLoginHandler(secret, func(email, password string) (*cboxid.LegacyUser, error) {
    row, err := db.FindUser(email)
    if err != nil {
        return nil, err // could not decide → 503
    }
    if row == nil || !bcrypt.Match(row.Hash, password) {
        return nil, nil // no
    }

    return &cboxid.LegacyUser{Email: row.Email, Name: row.Name, PasswordHash: row.Hash}, nil
})

http.Handle("/cbox-legacy", handler)
```

Returning `(nil, nil)` is a wrong password. **Returning an error is different**: your store
could not decide, and it answers 503 so Cbox ID refuses the sign-in rather than reading an
outage as a bad credential. The secret is checked when the handler is built, so a missing
one fails at startup rather than as a 500 that reads as an outage.

## Install

> **Where do `issuer`, `clientId` and `redirectUri` come from?**
> Register an app in your environment console — see
> [Integrate your app](https://github.com/cboxdk/cbox-id/blob/main/docs/getting-started/integrate-your-app.md).
> For a CLI, answer **"CLI or device"** and see
> [Sign in from a CLI](https://github.com/cboxdk/cbox-id/blob/main/docs/getting-started/sign-in-from-a-cli.md);
> it has no redirect URI and no secret.

```bash
go get github.com/cboxdk/id-go
```

## CLI login (device flow)

```go
client, _ := cboxid.NewDeviceClient(ctx, cboxid.DeviceConfig{
    Issuer:   "https://id.acme.com",
    ClientID: "cid_...", // register the app as "CLI or device" — there is no secret
    Scopes:   []string{"openid", "profile", "email", "offline_access"},
})

auth, _ := client.RequestDeviceAuthorization(ctx, cboxid.DeviceParams{})
fmt.Printf("Visit %s and enter code %s\n", auth.VerificationURI, auth.UserCode)

// Blocks until the user approves (or the code expires); honors the poll interval.
user, err := client.PollDeviceToken(ctx, auth)
fmt.Printf("Signed in as %s\n", user.Email)
// Persist user.Token (with its refresh token) to your CLI config for next time.
```

The scopes are bounded by what the app is REGISTERED for: a device request naming one
outside that ceiling is refused with `invalid_scope` rather than quietly reduced, because
there is no browser in front of it to notice a smaller grant.

A complete, runnable example is in [`examples/cli`](examples/cli).

## Server login (authorization code + PKCE)

```go
req, err := client.CreateAuthorizationRequest(cboxid.AuthParams{})
if err != nil {
    return err // ErrConfiguration: no RedirectURI, or contradictory params (below)
}
// persist req.State, req.CodeVerifier, req.Nonce and req.Organization;
// redirect the user to req.URL

// on the callback:
q := r.URL.Query()
user, err := client.Authenticate(ctx,
    cboxid.Callback{
        Code:             q.Get("code"),
        State:            q.Get("state"),
        Error:            q.Get("error"),
        ErrorDescription: q.Get("error_description"),
    },
    cboxid.Stored{State: req.State, CodeVerifier: req.CodeVerifier, Nonce: req.Nonce, Organization: req.Organization},
)
```

`AuthParams.Prompt` takes one value or several (sent space-separated): `PromptNone`,
`PromptLogin`, `PromptConsent`, `PromptSelectAccount`, `PromptSelectOrganization`,
`PromptCreateOrganization`. `PromptNone` combined with anything else is refused before a
URL is built (OIDC Core §3.1.2.1).

`user.SessionID` is the id_token's `sid`, read from the signed id_token only. Keep it to
match an OIDC back-channel logout, which names the session by `sid`.

## Organizations

A sign-in can be bound to one organization. The tokens then carry `org`, `org_name`, the
person's membership tier in it (`org_role`), and the app `roles` / `permissions` they hold
**there**. So switching organization means a new authorization, not a flag on the old
session.

```go
// Bind to an organization you already know (the person must be an active member):
req, err := client.CreateAuthorizationRequest(cboxid.AuthParams{Organization: "org_2x…"})

// Always show the hosted organization picker, with your guess preselected:
req, err = client.CreateAuthorizationRequest(cboxid.AuthParams{
    Prompt:           []cboxid.Prompt{cboxid.PromptSelectOrganization},
    OrganizationHint: "org_2x…",
})

// Hosted "create a team" step; the person becomes its owner and the sign-in
// continues bound to the new organization:
req, err = client.CreateAuthorizationRequest(cboxid.AuthParams{
    Prompt: []cboxid.Prompt{cboxid.PromptCreateOrganization},
})
```

| Field | Sent as | Meaning |
|---|---|---|
| `Organization` | `organization` | Bind the sign-in to this organization. |
| `OrganizationHint` | `organization_hint` | Preselect it in the picker; the person may choose another. |
| `PromptSelectOrganization` | `prompt=select_organization` | Always show the picker. |
| `PromptCreateOrganization` | `prompt=create_organization` | Create an organization first. |

`Organization` cannot be combined with either organization prompt. It has already made
the choice they ask the person to make, so `CreateAuthorizationRequest` returns
`ErrConfiguration` rather than sending the combination. Use `OrganizationHint` with the
picker instead. An empty `Organization` or `OrganizationHint` means "not set" and is left
off the URL.

### Switching

`client.SwitchOrganization(id, cboxid.AuthParams{})` is `CreateAuthorizationRequest` with
`Organization` set, under a name that says what it is for. Persist and redirect exactly as
for a sign-in. Cbox ID already has the person's session, so they normally come straight
back without seeing a form.

```go
func switchOrganization(w http.ResponseWriter, r *http.Request) {
    req, err := client.SwitchOrganization(r.URL.Query().Get("org"), cboxid.AuthParams{})
    if err != nil {
        http.Error(w, "unknown organization", http.StatusBadRequest)
        return
    }
    saveAuthState(w, req) // State, CodeVerifier, Nonce and Organization
    http.Redirect(w, r, req.URL, http.StatusFound)
}
```

**The binding is checked, not trusted.** The request echoes `Organization`. Persist it with
the rest and pass it back as `Stored.Organization`, and `Authenticate` refuses tokens for
any other organization. An instance that predates organization selection ignores the
parameter and answers for whichever organization the session already had. Without the
check, your app would show the new organization's name over the old one's data.

Replace your session with the user the callback returns rather than patching the old one:
`org_role`, `roles` and `permissions` can all differ between organizations. A person who
is not (or no longer) an active member comes back with `error=access_denied`:

```go
user, err := client.Authenticate(ctx, callback, stored)
var oauthErr *cboxid.OAuthError
if errors.As(err, &oauthErr) && oauthErr.Code == "access_denied" {
    // Not a member of that organization. Send them back to the one they were in.
}
```

### Reading the claims

The signed-in user carries them typed:

```go
user.Organization // *cboxid.ActiveOrganization{ID, Name, Role}, nil when unbound
user.Roles        // []string
user.Permissions  // []string
user.Actor        // *cboxid.Actor{Subject, Actor}, nil unless a support session
```

The same helpers work on the user and on a claim set you verified yourself, such as an
access token's payload on a resource server:

```go
if !cboxid.HasPermission(claims, "invoices:create") { // claims is a map[string]any
    return errForbidden
}
if org := cboxid.OrganizationOf(user); org != nil && org.Role == cboxid.OrganizationRoleOwner {
    showBilling()
}
```

`OrganizationOf`, `ActorOf`, `IsSupportSession`, `RolesOf`, `PermissionsOf`, `HasRole` and
`HasPermission` accept a `*cboxid.CboxUser` or a `map[string]any` (convert a named map type
such as `jwt.MapClaims` with `map[string]any(claims)`). Matching is exact: `invoices:*`
does not grant `invoices:delete`. An `org_role` this SDK version does not recognise reads
as `""`, never as a tier it would have to guess. The roles are the `OrganizationRole`
constants `OrganizationRoleOwner`, `…Admin`, `…Developer`, `…Member` and `…Viewer`.

### Support sessions

A staff member can act as one of your users for a limited time (at most an hour, no refresh
token, with a recorded reason). Those tokens carry the RFC 8693 `act` claim naming the
staff member, and `IsSupportSession` reports it:

```go
if user.IsSupportSession() {
    // Show a banner, and refuse what a helper should never do on someone's behalf:
    // changing their password, their email, their payout details.
}
```

It is **fail-closed**: any non-null `act` claim counts, including one whose shape the SDK
cannot read (`user.Actor.Subject` is then `""`). A claim it cannot parse is not evidence
that nobody else is at the keyboard. A nested chain of actors is followed eight deep.

## Back-channel calls

```go
token, _ := client.MachineToken(ctx, cboxid.MachineTokenParams{Scopes: []string{"reports.read"}})
claims, _ := client.UserInfo(ctx, user.AccessToken)
result, _ := client.Introspect(ctx, someToken) // RFC 7662
err := client.Revoke(ctx, user.RefreshToken, cboxid.HintRefreshToken) // RFC 7009
```

Revoking a refresh token drops the whole token family — that's what "sign out
everywhere" needs. Both calls are confidential-client, so they require a `ClientSecret`.

## Verify webhooks

```go
ok := cboxid.VerifyWebhook(rawBody, r.Header.Get("X-Cbox-Signature"), webhookSecret, 300)
```

## Declare roles & permissions, publish a manifest

Declare your app's authorization **roles** and **permissions** in code and push them to
Cbox ID on deploy. Cbox ID owns identity and who holds what; your app owns what a role
_means_. Assigned roles then arrive in the token's claims for you to enforce. Requires a
`ClientSecret` and a client that holds the `apps.manifest` scope.

```go
client, _ := cboxid.New(ctx, cboxid.Config{
    Issuer:       "https://id.acme.com",
    ClientID:     "cid_...",
    ClientSecret: "csec_...",
    // No RedirectURI: publishing is a client-credentials call, not a sign-in.
    Permissions: []cboxid.Permission{
        {Key: "invoices:create", Description: "Create invoices"},
        {Key: "invoices:read", Description: "View invoices", TenantAssignable: true},
        {Key: "support:impersonate", Description: "Act as a customer"},
    },
    Roles: []cboxid.Role{
        {Key: "billing-admin", Name: "Billing Admin", Description: "Full billing access",
            Permissions: []string{"invoices:create", "invoices:read"}},
        {Key: "support", Name: "Support", Description: "Vendor support staff",
            Permissions: []string{"support:impersonate"}, StaffOnly: true},
    },
})

// Run on deploy. Idempotent — republishing an unchanged manifest is a no-op.
summary, err := client.PublishManifest(ctx)
// summary.Unchanged, summary.RolesDeclared, summary.PermissionsDeclared
```

Two flags decide what an organization's own admins may hand out, and their defaults are
opposite on purpose:

- **`Role.StaffOnly`** (default false) keeps a role to your own staff; organization admins
  never see it in their role picker. Roles are tenant-assignable unless they say so. It is
  sent as `"tenant_assignable": false`.
- **`Permission.TenantAssignable`** (default false) marks a self-serve permission that an
  organization's admins may grant in a custom role. Permissions are not self-serve unless
  they say so. It is sent as `"tenant_assignable": true`.

Neither key is sent at its default, so a catalog that uses neither pushes, and hashes,
exactly as it did before they existed.

`PublishManifest` mints a client-credentials token scoped to `apps.manifest`, then POSTs
the manifest to `{issuer}/api/v1/apps/manifest`. A rejected push wraps
`cboxid.ErrManifestRejected`. A complete example is in
[`examples/publish-manifest`](examples/publish-manifest). This mirrors the Laravel
client's `php artisan cbox-id:publish-manifest`, so the manifest contract is identical
across SDKs.

## Errors

Errors wrap the sentinels `cboxid.ErrInvalidState`, `cboxid.ErrAuthentication` and
`cboxid.ErrConfiguration` — match them with `errors.Is`. A state mismatch is
`ErrInvalidState`; treat it as a fresh start, not a user-facing error.

An OAuth error keeps the server's own answer as a `*cboxid.OAuthError` (match it with
`errors.As`; it is still `ErrAuthentication`). Its `Code` is the RFC 6749 error code: from
the token endpoint (`invalid_grant` on a refresh means the session is over), or from the
callback's `error` parameter, where `Op` is `"authorization"`.

## Security & scope

Login is hardened by default — PKCE, `state`, nonce (auth-code flow), and full
id_token verification (signature/issuer/audience) via go-oidc. Key accounts on
`user.ID` (the stable subject), not on email.

This is a **client**. It authenticates users, binds a sign-in to an organization, and calls
a Cbox ID instance's standard endpoints. It does not configure SSO, run SCIM, or administer
organizations (members, invitations, billing): those are platform capabilities of
[`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id).

Report vulnerabilities via this repo's GitHub **Private Vulnerability Reporting**.

## License

MIT © Cbox.
