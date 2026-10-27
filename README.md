# OBreaker — OAuth Authorization Bypass Exploit Tool

**Full end-to-end exploitation of 17 OAuth/OIDC bypass techniques.**

OBreaker goes beyond detection — every finding completes the full **Find → Forge → Fire** attack chain: detect the vulnerability, craft an exploit payload, exchange for an access token, access protected resources, and prove identity theft with decoded JWT claims.

Built to test against [BRuteLogic's OAuth Testbed](https://403.brutelogic.net/authz/oauth), and adaptable to any OAuth 2.0 / OpenID Connect authorization server.

---

## Features

- **17 exploit techniques** covering PKCE bypass, state manipulation, grant type abuse, token replay, scope escalation, and more
- **Full attack chains** — not just detection, but complete exploitation with proof of resource access
- **Structured evidence** — every finding includes the HTTP request/response chain, JWT claim decode, and impact statement
- **OpenID Connect discovery** — auto-discovers endpoints via `.well-known/openid-configuration`
- **JSON + terminal reports** — color-coded terminal output with FIND/FORGE/FIRE phase markers, plus machine-readable JSON
- **Concurrent scanning** — parallel technique execution for speed
- **Zero external dependencies** beyond `requests`

---

## Techniques

| # | Key | Technique | Severity | Description |
|---|-----|-----------|----------|-------------|
| 1 | `response-mode` | Response Mode Escape | Critical | `redirect_uri` not validated across response modes — code delivered to attacker-controlled URI |
| 2 | `state-missing` | Missing State | Critical | No CSRF state issued or validated — login CSRF enables account takeover |
| 3 | `state-static` | Static State | Critical | Static state value shared across all sessions — replay in CSRF attack |
| 4 | `state-predictable` | Predictable State | Critical | State derived from timestamp — predictable, enabling CSRF |
| 5 | `pkce-plain` | S256→plain Downgrade | Critical | `plain` method accepted when `S256` registered — verifier exposed in transit |
| 6 | `pkce-noverifier` | No Verifier Check | Critical | Token endpoint skips `code_verifier` validation entirely |
| 7 | `pkce-nochallenge` | No Challenge Required | Critical | PKCE not enforced at authorization — code issued without `code_challenge` |
| 8 | `pkce-confidential` | Confidential Client Downgrade | Critical | Confidential client exchanges code without verifier — PKCE bypassed |
| 9 | `aud-validation` | Missing aud Validation | Critical | Resource server doesn't validate JWT `aud` claim — cross-service token replay |
| 10 | `race-condition` | OAuth Singleton Race | Critical | Shared singleton verifier state — concurrent requests enable cross-session code exchange |
| 11 | `prompt-none` | prompt=none Silent Redirect | Critical | `redirect_uri` not validated with `prompt=none` — silent code theft |
| 12 | `dcr` | Dynamic Client Registration | Medium | Registration endpoint exposed — rogue client registration possible |
| 13 | `grant-type-mfa` | Grant Type → MFA Bypass | Critical | Password grant bypasses browser-bound MFA entirely |
| 14 | `auth-method` | Auth Method Confusion | Critical | `private_key_jwt` registered but `client_secret_basic` accepted as fallback |
| 15 | `code-replay` | Code Replay | Critical | Authorization code reusable multiple times — no single-use enforcement |
| 16 | `scope-creep` | Scope Creep at Refresh | Critical | Refresh token issues broader scope than originally granted (RFC 6749 §6) |
| 17 | `resource-indicator` | Resource Indicator Omission | Critical | Resource indicator (RFC 8707) ignored — audience-unbound token issued |

---

## Installation

```bash
# Clone
git clone https://github.com/virgilcj/obreaker.git
cd obreaker

# Only dependency
pip install requests
```

Python 3.8+ required. No other dependencies.

---

## Usage

### Scan all techniques against a target

```bash
python obreaker.py --target https://403.brutelogic.net/authz/oauth --all
```

### Run a single technique

```bash
python obreaker.py --target https://403.brutelogic.net/authz/oauth --technique pkce-plain
```

### Discovery mode (enumerate endpoints only)

```bash
python obreaker.py --target https://403.brutelogic.net/authz/oauth --discover
```

### JSON output

```bash
python obreaker.py --target https://403.brutelogic.net/authz/oauth --all --json results.json
```

### List available techniques

```bash
python obreaker.py --list
```

---

## Output

### Terminal

Each finding shows the complete attack chain with color-coded phases:

```
[CRITICAL] Response Mode Escape
  redirect_uri not validated across response modes

  ATTACK CHAIN:
    [FIND]  GET /response-mode → redirect_uri not validated
    [FORGE] Set redirect_uri=https://attacker.com/cb → code stolen to attacker
    [FIRE]  POST /token with stolen code → JWT access_token obtained
    [FIRE]  GET /api with Bearer token → protected resource accessed

  PROOF OF EXPLOITATION:
    Identity: user (user@testbed.local)
    Impact: Attacker steals authorization code via unvalidated redirect...
    JWT Claims: sub=user, iss=https://403.brutelogic.net, ...
```

### JSON

The `--json` flag writes structured output with full attack chains and proof objects:

```json
{
  "findings": [
    {
      "technique": "response-mode",
      "severity": "Critical",
      "title": "Response Mode Escape",
      "chain": [
        {"phase": "FIND", "action": "...", "result": "...", "success": true},
        {"phase": "FORGE", "action": "...", "result": "..."},
        {"phase": "FIRE", "action": "...", "result": "..."}
      ],
      "proof": {
        "identity_obtained": "user (user@testbed.local)",
        "jwt_claims": {"sub": "user", "iss": "...", "aud": "..."},
        "resource_accessed": true,
        "impact": "..."
      }
    }
  ]
}
```

---

## How It Works

OBreaker follows the **FFF methodology** (Find, Forge, Fire) from [BRuteLogic's Broken Token](https://brutelogic.net/ebooks/broken-token/oauth/):

1. **Find** — Detect the vulnerability by probing the authorization server's behavior (missing parameters, downgraded methods, accepted grant types)
2. **Forge** — Craft the exploit payload: steal an authorization code via unvalidated redirect, forge a PKCE bypass, submit a password grant to skip MFA, etc.
3. **Fire** — Complete the attack: exchange the code/grant for a JWT access token, access protected resources with it, decode the JWT to prove identity theft

Every technique that fires successfully proves **actual resource access** — not just "this parameter is missing" but "I accessed `/api` as `user@testbed.local` with role `user`."

---

## Research & References

### Standards
- [RFC 6749](https://tools.ietf.org/html/rfc6749) — OAuth 2.0 Authorization Framework
- [RFC 7636](https://tools.ietf.org/html/rfc7636) — PKCE
- [RFC 8707](https://tools.ietf.org/html/rfc8707) — Resource Indicators
- [RFC 9700](https://tools.ietf.org/html/rfc9700) — OAuth 2.0 Security Best Current Practice (Jan 2025)
- [OWASP WSTG 4.5.5](https://owasp.org/www-project-web-security-testing-guide/) — Testing OAuth

### CVEs Covered
- CVE-2023-6134 / CVE-2023-6291 / CVE-2023-6927 — Keycloak response mode chain
- CVE-2023-31999 — Static state (Nextcloud)
- CVE-2024-23647 — Auth method confusion (Authentik)
- CVE-2024-37893 — Redirect URI bypass (CAS)
- CVE-2024-52289 — Regex redirect URI (Authentik)

### Inspired By
- [BRuteLogic's OBroken](https://403.brutelogic.net/authz/oauth) — OAuth Bypass Testbed
- [Broken Token: OAuth](https://brutelogic.net/ebooks/broken-token/oauth/) — 13 (now 17) Original OAuth Attack Techniques

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Only use it against applications you have explicit permission to test. The author is not responsible for misuse.

---

## License

MIT
