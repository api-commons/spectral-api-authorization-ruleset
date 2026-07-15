# Spectral API Authorization Ruleset

**A curated, owned, grounded [Stoplight Spectral](https://github.com/stoplightio/spectral) ruleset for the [API Authorization Profile](https://apicommons.org/api-authorization) — lint your API's authorization posture against OAuth 2.1 and FAPI 2.0 at two tiers, in one line.**

`@api-common/spectral-api-authorization-ruleset` turns "we use OAuth" into something you can **check on every commit**. It encodes a two-tier authorization profile — **`normal`** (grounded in [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) / OAuth 2.1) and **`high`** ([FAPI 2.0](https://openid.net/specs/fapi-2_0-security-profile.html)) — as Spectral rules that use **built-in functions only** (no custom JavaScript), so it runs anywhere Spectral runs.

Why this exists: the standards for secure API authorization already exist — the problem is that almost nobody checks their API against them. This ruleset is the "profile, don't invent" idea made executable: every rule names the RFC or FAPI clause it enforces. It was generalized from Germany's federal [API authorization *Sicherheitsvorgaben*](https://gitlab.opencode.de/sachsen-anhalt/mid/foederale-api-autorisierungsinfrastruktur) into a standard-neutral form any API program — public or private — can adopt.

One of the [API Commons tools](https://apicommons.org/tools/), alongside [Spectral OWASP Ruleset](https://github.com/api-commons/spectral-owasp-ruleset), [Spectral Reporter](https://reporter.apicommons.org), [API Validator](https://validator.apicommons.org), and [Ruleset Commons](https://rulesets.apicommons.org).

## Two lint targets, because the posture lives in two artifacts

An OpenAPI document can't carry the whole story. The FAPI-specific truth — DPoP, PAR, client-authentication methods, PKCE — lives in the authorization server's own metadata. So this package ships **two rulesets**, and you run each against the artifact it applies to:

| Ruleset | Lint this artifact | Checks |
|---|---|---|
| `api-authorization-openapi.yaml` | your **OpenAPI** (3.x) | security scheme contract, global/operation `security`, declared scopes, transport, and the shape of OAuth flows (bans `implicit`/`password`) |
| `api-authorization-oauth-metadata.yaml` | your **OAuth AS metadata** ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) `/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`) | client auth (`private_key_jwt`/mTLS), sender-constraining (DPoP/mTLS), PAR, PKCE `S256`, response types, the mix-up `iss` parameter, signing algorithms, endpoint discovery |

```sh
# lint your OpenAPI
spectral lint openapi.yaml -r api-authorization-openapi.yaml

# lint your authorization server metadata
curl -s https://as.example.gov/.well-known/openid-configuration -o as-metadata.json
spectral lint as-metadata.json -r api-authorization-oauth-metadata.yaml
```

Adopt by reference from [ruleset-commons](https://rulesets.apicommons.org) or npm and inherit updates instead of forking a frozen copy.

## The floor — what this does NOT prove

Static conformance to this profile is **necessary, not sufficient**. Linting checks the **declared contract**, not the running system. It cannot verify a live DPoP proof, real token binding, a working PAR endpoint, that revocation actually revokes, or that object-/function-level authorization is correct (that is OWASP API1/API5 — use the [OWASP ruleset](https://github.com/api-commons/spectral-owasp-ruleset) alongside this one). A clean report means the contract is not leaving an obvious door open; the rest is owed to your code, your tests, and your gateway. Advertising `require_pushed_authorization_requests: true` in metadata is proof the server *claims* to require PAR — not proof it enforces it.

## Tiers

Every rule is tagged `normal` or `high` in its description. `high` is a strict superset — every `normal` requirement also applies at `high`. The `high`-only rules are the FAPI-grade ones: code-only response types, the mix-up `iss` parameter, PKCE `S256`, strong client authentication, sender-constraining, PAR, and asymmetric-only signing. Run the full ruleset for a `high`-assurance API; for a `normal`-tier API, disable the `high` rules via a thin extending ruleset:

```yaml
# api-authorization-normal.yaml
extends: ["./api-authorization-oauth-metadata.yaml"]
rules:
  authz-meta-response-types-code-only: off
  authz-meta-iss-parameter: off
  authz-meta-pkce-s256: off
  authz-meta-client-auth-no-secret: off
  authz-meta-client-auth-strong: off
  authz-meta-sender-constraining: off
  authz-meta-par-required: off
  authz-meta-asym-signing: off
```

## Grounded, owned rules

Every rule carries its provenance, modelling what a governance rule *should* look like:

- a stable **id** (e.g. `authz-meta-sender-constraining`)
- a **description** naming the requirement (e.g. `SC-1 (high)`) and the risk
- a **message** shown on each finding
- a **severity** (`error` for MUST, `warn` for SHOULD)
- a **documentationUrl** deep-linking the profile requirement

### Rules

**OpenAPI target** — `authz-transport-https-servers`, `authz-security-schemes-defined`, `authz-global-security-defined`, `authz-grant-no-implicit`, `authz-grant-no-password`, `authz-grant-types-allowed`, `authz-oauth2-https-urls`, `authz-oauth2-scopes-defined`.

**OAuth AS Metadata target** — `authz-meta-issuer-https`, `authz-meta-endpoints-present`, `authz-meta-no-implicit-response-type`, `authz-meta-grant-no-password`, `authz-meta-response-types-code-only`, `authz-meta-iss-parameter`, `authz-meta-pkce-s256`, `authz-meta-client-auth-no-secret`, `authz-meta-client-auth-strong`, `authz-meta-sender-constraining`, `authz-meta-par-required`, `authz-meta-no-none-alg`, `authz-meta-asym-signing`.

See [the profile](https://apicommons.org/api-authorization) for each requirement's grounding clause (RFC / FAPI section).

## Provenance

RFC 9700 (OAuth 2.0 Security BCP), OAuth 2.1 (`draft-ietf-oauth-v2-1`), FAPI 2.0 Security Profile, RFC 8414 (AS Metadata), RFC 9449 (DPoP), RFC 8705 (mTLS), RFC 9126 (PAR), RFC 7636 (PKCE), RFC 9207 (`iss`), RFC 8725 (JWT BCP). Generalized from the German federal *Föderale API-Autorisierungsinfrastruktur*.

## Test

`npm test` lints the noncompliant + clean fixtures for both targets and asserts every expected rule fires on the noncompliant fixtures, the clean fixtures are silent, and no rule throws.

## License

Apache-2.0 — Copyright 2026 API Commons (Kin Lane).
