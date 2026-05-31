# Runbook — Internal Bearer-Token Rotation

**Applies to:** the shared internal bearer token that authenticates
`POST /api/v1/decisions/internal` (admission-webhook → policy-manager) and the
dashboard ingest endpoint.
**Controls:** SC-12, SC-13, IA-5(1) (CRY-WU-14).
**Audience:** platform operators.

## Background

The internal token is a shared secret. Verification is constant-time
(`internal/auth`, CRY-WU-13/IAM-WU-07), and the verifier accepts **two** tokens
at once — a *current* and a *previous* — so the secret can be rotated with no
downtime: callers presenting either token are accepted during the rotation
window.

Environment variables consumed by the binaries:

| Service | Current token | Previous token (rotation window) |
|---|---|---|
| policy-manager | `POLICY_MANAGER_INTERNAL_TOKEN` | `POLICY_MANAGER_INTERNAL_TOKEN_PREVIOUS` |
| dashboard | `INTERNAL_TOKEN` | `INTERNAL_TOKEN_PREVIOUS` |
| admission-webhook (sender) | `POLICY_MANAGER_INTERNAL_TOKEN` | — (sender presents the current token) |

An empty token disables the endpoint (every request returns 401); an empty
*previous* token is simply ignored and does not widen what is accepted.

## Generating a token (FIPS CSPRNG)

Generate the new token from a FIPS-validated CSPRNG — **not** from a
template-time RNG such as Helm's `randAlphaNum`. Any of:

- A short Go program / the project tooling calling `auth.GenerateToken` (which
  reads `crypto/rand`; under the GOFIPS140 build this is the validated DRBG).
- `openssl rand -base64 32` on a FIPS-enabled host.

```console
$ NEW=$(openssl rand -base64 32 | tr -d '\n')
```

## Rotation procedure (zero downtime)

1. **Record the old token as previous.** Set the previous-token variables on
   the verifying services (policy-manager, dashboard) to the value currently in
   use, and roll them so both old and new are accepted:
   - `POLICY_MANAGER_INTERNAL_TOKEN_PREVIOUS = <old token>`
   - `INTERNAL_TOKEN_PREVIOUS = <old token>`
2. **Set the new current token** on every service that holds it
   (admission-webhook sender, policy-manager, dashboard):
   - `POLICY_MANAGER_INTERNAL_TOKEN = $NEW` (webhook + policy-manager)
   - `INTERNAL_TOKEN = $NEW` (dashboard)
   Update the backing `*-internal-token` Secret accordingly.
3. **Roll the pods.** During the window the webhook presents `$NEW`; the
   policy-manager/dashboard accept both `$NEW` and the old token, so any
   in-flight or not-yet-rolled caller is still authorized.
4. **Close the window.** Once all pods run `$NEW`, clear the previous-token
   variables (`..._PREVIOUS=""`) and roll again. Only `$NEW` is now accepted;
   the old token is retired.

## Verification

- A request bearing `$NEW` to `POST /api/v1/decisions/internal` returns `204`.
- During the window, a request bearing the old token also returns `204`.
- After the window is closed, the old token returns `401`.

## Key-compromise response

If a token is believed compromised, **skip the window**: set `$NEW` everywhere,
leave the previous-token variables empty, and roll immediately. The compromised
token is rejected as soon as each pod restarts.

## Status / scope

- The two-token rotation window is implemented and unit-tested in
  `internal/auth` (`TestTokenVerifier_RotationWindow`).
- Wiring the chart to generate the token from a CSPRNG Job (replacing the
  demo-only `randAlphaNum` autogeneration) and to surface the previous-token
  Secret key is tracked as the remaining Helm portion of CRY-WU-14.
