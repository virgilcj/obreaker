# BRuteLogic OAuth Testbed — Endpoint Analysis

**Base**: `https://403.brutelogic.net/authz/oauth`
**Client ID**: `c_vli7zo11`
**Redirect URI**: `https://403.brutelogic.net/authz/oauth/cb`
**OpenID Config**: `https://403.brutelogic.net/.well-known/openid-configuration`

## Discovery

The `.well-known/openid-configuration` is at the root domain (not under /authz/oauth).
Returns all endpoints, supported grant types, response modes, scopes, PKCE methods.

Key discovery data:
- `grant_types_supported`: authorization_code, refresh_token, **password**, device_code
- `response_modes_supported`: query, fragment, form_post, form_post.jwt
- `token_endpoint_auth_methods_supported`: client_secret_basic, client_secret_post, private_key_jwt, none
- `code_challenge_methods_supported`: S256, plain
- `scopes_supported`: openid, email, profile, read, write, admin, offline_access
- `resource_parameter_supported`: true
- Registration endpoint exposed: `/authz/oauth/register`

## Core Flow

1. `/authorize` — requires `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`
2. Returns 302 redirect to `redirect_uri?code=<hex>&state=<state>`
3. `/token` — POST with `grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, `code_verifier`
4. Returns JWT access_token + refresh_token + aud metadata

## Per-Endpoint Findings

### 1. Response Mode Escape (`/response-mode`)
- **Method**: GET with authorize params + `response_mode=<mode>`
- **Vuln**: redirect_uri NOT validated. Code delivered to ANY URI across ALL response_modes.
- **Key**: When tested without redirect_uri, defaults to `https://attacker.com/cb`
- **Response**: JSON with `location`, `mode_used`, `note`
- **Exploit**: Set `redirect_uri=https://attacker.com/cb` with any response_mode → code stolen

### 2. Missing State (`/state?technique=missing`)
- **Method**: GET with authorize params, NO state param needed
- **Vuln**: State not issued or validated. CSRF possible.
- **Response**: `{"code":"<hex>","note":"state not issued or validated — CSRF possible"}`
- **Exploit**: Omit state from authorize request → code issued without CSRF protection

### 3. Static State (`/state?technique=static`)
- **Method**: GET with authorize params
- **Vuln**: Static state value shared across ALL sessions (CVE-2023-31999 pattern)
- **Response**: Always returns `state: "static-state-value-aabbccdd"` regardless of input
- **Exploit**: Observe one flow's state → replay in CSRF attack, always matches

### 4. Predictable State (`/state?technique=predictable`)
- **Method**: GET with authorize params
- **Vuln**: State derived from timestamp — predictable
- **Response**: Returns `state: "state-<base36_timestamp>"` — increments with time
- **Exploit**: Observe two states close in time → derive pattern → predict future states

### 5. S256→plain Downgrade (`/pkce?technique=plain`)
- **Method**: GET with authorize params (any code_challenge_method)
- **Vuln**: plain method accepted even when S256 was registered. Method evaluated per-request.
- **Response**: `{"code":"<hex>","note":"plain method accepted — S256->plain downgrade confirmed","method_accepted":"S256"}`
- **POST variant**: Returns `method_accepted: "plain"` confirming downgrade
- **Exploit**: Send code_challenge_method=plain at token exchange → use challenge as verifier directly

### 6. No Verifier Check (`/pkce?technique=noverifier`)
- **Method**: GET with authorize params
- **Vuln**: Token endpoint skips code_verifier check entirely
- **Response**: `{"code":"<hex>","note":"code issued — token endpoint skips verifier check"}`
- **Exploit**: Exchange code without sending code_verifier → PKCE defeated

### 7. No Challenge Check (`/pkce?technique=nochallenge`)
- **Method**: GET with authorize params — code_challenge NOT required
- **Vuln**: PKCE not enforced at authorization — code issued without code_challenge
- **Response**: `{"code":"<hex>","note":"code issued without code_challenge — PKCE not required"}`
- **Exploit**: Omit code_challenge from authorize → code issued → exchange without PKCE

### 8. Confidential Client Downgrade (`/pkce?technique=confidential`)
- **Method**: GET with authorize params
- **Vuln**: Confidential client can exchange code without verifier
- **Response**: `{"code":"<hex>","note":"confidential client PKCE downgrade — verifier not enforced at exchange"}`
- **Exploit**: Client with client_secret exchanges code without code_verifier → PKCE bypassed for confidential clients

### 9. Missing aud Validation (`/aud-validation` + `/api`)
- **Method**: GET `/api` with `Authorization: Bearer <token>`
- **Vuln**: Resource server (`/api`) does NOT validate the `aud` claim in the token
- `/aud-validation` itself returns 401 always (it's the "secure" counterpart)
- **Response from /api**: `{"sub":"user","aud_validated":false,"note":"aud not validated — any token from this AS accepted"}`
- **Exploit**: Get a token with `aud: "https://api-a.com"` → use it at `/api` (different audience) → accepted

### 10. OAuth Singleton Race Condition (`/race`)
- **Method**: GET with authorize params
- **Vuln**: Shared singleton verifier state — concurrent requests overwrite each other
- **Response**: `{"code":"<hex>","state":"<state>","note":"Singleton race — shared verifier state overwritten. Cross-verifier exchange will succeed."}`
- **Exploit**: Two concurrent auth flows → second flow's verifier overwrites first → attacker exchanges victim's code with attacker's verifier

### 11. prompt=none Silent Redirect (`/prompt-none`)
- **Method**: GET with authorize params + `prompt=none`
- **Vuln**: redirect_uri NOT validated. Code delivered to unregistered URI.
- **Response**: 302 with `{"location":"<attacker_uri>?code=<hex>","redirect_uri_validated":false,"note":"..."}`
- **Exploit**: Set `redirect_uri=https://attacker.com/cb&prompt=none` → silent redirect delivers code to attacker without user interaction

### 12. DCR Open Registration (`/register`)
- **Method**: POST with JSON body
- **Current behavior**: Returns 401 "registration requires authentication"
- **Finding**: The endpoint EXISTS (discovered via .well-known), is live (401 not 404), and the vulnerability class is: if auth is weak/missing, attacker registers a rogue client with arbitrary redirect_uris
- **Note**: The testbed may simulate this as a detection exercise — tool should flag the endpoint's existence + attempt registration

### 13. Grant Type Substitution → MFA Bypass (`/token/mfa`)
- **Method**: POST with `grant_type=password&username=user&password=pass&client_id=c_vli7zo11`
- **Vuln**: MFA bound to browser flow only. Password grant bypasses MFA entirely.
- **Response**: `{"access_token":"<jwt>","note":"MFA bypassed — password grant accepted without MFA check"}`
- **Key**: `grant_type=authorization_code` returns "unsupported_grant_type" here — only password works
- **Exploit**: If password grant is supported (check .well-known), use it to bypass browser-bound MFA

### 14. Auth Method Confusion (`/token/authmethod`)
- **Method**: POST with `Authorization: Basic <base64(client_id:anything)>`
- **Vuln**: Client registered with private_key_jwt but client_secret_basic accepted as fallback
- **Hint**: Returns `"note": "send Basic auth to trigger downgrade"` when Basic auth not sent
- **Response with Basic**: `{"access_token":"<jwt>","note":"Auth method downgrade confirmed — private_key_jwt registered but client_secret_basic accepted"}`
- **Exploit**: Client registered for strong auth (private_key_jwt) → send weak Basic auth → accepted

### 15. Code Replay (`/token/replay`)
- **Method**: POST with standard authorization_code exchange
- **Vuln**: Same authorization code can be exchanged MULTIPLE times
- **Response**: Returns valid token on each replay — no one-time-use enforcement
- **Exploit**: Intercept code → exchange it → victim also exchanges it → both get tokens (or attacker replays intercepted code)

### 16. Scope Creep at Refresh (`/token/scope`)
- **Method**: POST with `grant_type=refresh_token&refresh_token=<rt>&client_id=<cid>&scope=openid read write admin`
- **Vuln**: Refresh endpoint issues token with broader scope than originally granted (RFC 6749 §6 silence)
- **Response**: `{"access_token":"<jwt>","scope":"openid read write admin","note":"Scope issued as requested — no ceiling check"}`
- **Exploit**: Get token with `scope=read` → refresh with `scope=read write admin` → escalated

### 17. Resource Indicator Omission (`/token/resource`)
- **Method**: POST with standard exchange, resource param optional
- **Vuln**: Resource indicator (RFC 8707) ignored — audience-unbound token issued
- **Response**: `{"access_token":"<jwt>","aud_present":false,"note":"Resource indicator ignored — audience-unbound token"}`
- **Key**: Even when `resource=https://api.target.com` is sent, token still has NO aud
- **Exploit**: Omit resource → get audience-unbound token → use at any resource server

## Token Exchange Summary

| Endpoint | Grant Type | Extra Params | Key Detection Signal |
|---|---|---|---|
| /token | authorization_code | code_verifier | Normal (secure) exchange |
| /token/mfa | **password** | username, password | MFA bypassed note |
| /token/authmethod | authorization_code | Basic auth header | Downgrade confirmed note |
| /token/replay | authorization_code | (replay same code) | Token on 2nd exchange |
| /token/scope | **refresh_token** | scope escalation | Broader scope in response |
| /token/resource | authorization_code | resource param ignored | aud_present: false |
