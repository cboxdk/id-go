# Changelog

All notable changes to `github.com/cboxdk/id-go` are recorded here. Earlier releases are
described in their [GitHub releases](https://github.com/cboxdk/id-go/releases).

## Unreleased

Organization selection, support sessions, and staff roles in the manifest. Needs a Cbox ID
instance that understands the `organization` / `organization_hint` authorize parameters,
emits `org_role` and `act`, and reads `tenant_assignable` in a manifest (laravel-id 1.19).
Against an older instance the new fields stay empty, and a switch fails at the callback
instead of silently landing in the old organization (see below).

### Added

- `AuthParams.Organization` (bind the sign-in to one organization) and
  `AuthParams.OrganizationHint` (preselect it in the hosted picker), plus the `Prompt` type
  with `PromptNone`, `PromptLogin`, `PromptConsent`, `PromptSelectAccount`,
  `PromptSelectOrganization` and `PromptCreateOrganization`.
- `client.SwitchOrganization(id, params)`: a new authorization bound to another
  organization.
- The organization a sign-in was bound to is echoed as `AuthorizationRequest.Organization`
  and checked at the callback through `Stored.Organization`: tokens for any other
  organization are refused.
- `CboxUser` gains typed `Organization` (`*ActiveOrganization{ID, Name, Role}` from `org`,
  `org_name`, `org_role`), `Roles`, `Permissions`, `Actor` (the RFC 8693 `act` claim) and
  `SessionID` (the id_token's `sid`, for matching back-channel logout), and the methods
  `IsSupportSession()`, `HasRole()` and `HasPermission()`.
- Claim helpers that take a `*CboxUser` or a `map[string]any` you verified yourself:
  `OrganizationOf`, `ActorOf`, `IsSupportSession`, `RolesOf`, `PermissionsOf`, `HasRole`,
  `HasPermission`. New types `OrganizationRole` (with `OrganizationRoleOwner`, `…Admin`,
  `…Developer`, `…Member`, `…Viewer`), `ActiveOrganization`, `Actor` and `ClaimSource`.
- `Role.StaffOnly`: a role only your own staff may assign, sent as
  `"tenant_assignable": false`. `Permission.TenantAssignable`: a self-serve permission an
  organization's admins may grant, sent as `"tenant_assignable": true`. Neither key is sent
  at its default, so an existing catalog's manifest and version do not change.
- `Callback.ErrorDescription`.

### Changed

- **BREAKING:** `CreateAuthorizationRequest` returns `(AuthorizationRequest, error)`. It
  returns `ErrConfiguration`, before any redirect, for `Organization` combined with
  `PromptSelectOrganization` or `PromptCreateOrganization`, and for `PromptNone` combined
  with another prompt (OIDC Core §3.1.2.1). A client without a `RedirectURI` now gets
  `ErrConfiguration` here instead of a panic. Update each call site to
  `req, err := client.CreateAuthorizationRequest(…)`.
- **BREAKING:** `AuthParams.Prompt` is `[]Prompt` instead of `string`. Replace
  `Prompt: "login"` with `Prompt: []cboxid.Prompt{cboxid.PromptLogin}`.
- An error returned to the callback (`?error=access_denied`) is now an `*OAuthError` with
  `Op: "authorization"`, `Code` and `Description`, as the token-endpoint errors already
  were. It still matches `errors.Is(err, ErrAuthentication)`. A refused organization switch
  is `access_denied`, and an app answers it by staying where it is, not by signing the
  person out, which it could not tell apart before.
- `Role` encodes and decodes its own JSON (`MarshalJSON` / `UnmarshalJSON`). The wire shape
  is unchanged apart from `tenant_assignable`, and decoding refuses a non-boolean
  `tenant_assignable` as the server does.

### Fixed

- The manifest checksum de-duplicates each role's permission references, as the server's
  parser does before it hashes, so a role naming a permission twice now gets the same
  version the server computes.
- The README and `examples/publish-manifest` no longer set a `RedirectURI` "required" for
  publishing; `New` has not required one since v0.11.0.
