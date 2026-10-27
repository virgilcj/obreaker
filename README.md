# OBreaker — OAuth Authorization Bypass Exploit Tool

**Full end-to-end exploitation of 17 OAuth/OIDC bypass techniques against any OAuth 2.0 server.**

OBreaker goes beyond detection — every finding completes the full **Find -> Forge -> Fire** attack chain: detect the vulnerability, craft an exploit payload, exchange for an access token, access protected resources, and prove identity theft with decoded JWT claims.

Works against **any OAuth 2.0 / OpenID Connect** implementation. Point it at a target, and it probes the standard `/authorize` and `/token` endpoints with behavioral analysis to detect real vulnerabilities.

---

## Features

- **17 exploit techniques** covering PKCE bypass, state manipulation, grant type abuse, token replay, scope escalation, and more
- **Generic by default** — probes standard OAuth endpoints, works against any authorization server
- **Profile mode** — built-in endpoint mappings for known vulnerable testbeds (`--profile brutelogic`)
- **Full attack chains** — not just detection, but complete exploitation with proof of resource access
- **Behavioral detection** — compares server responses with/without security parameters to identify misconfigurations
- **Structured evidence** — every finding includes the HTTP request/response chain, JWT claim decode, and impact statement
- **OpenID Connect discovery** — auto-discovers endpoints via `.well-known/openid-configuration`
- **Flexible auth** — supply `--code`, `--credentials`, or `--refresh-token` for full exploitation chains
- **JSON + terminal reports** — color-coded terminal output with FIND/FORGE/FIRE phase markers, plus machine-readable JSON
- **Zero external dependencies** beyond `requests`

---

## Techniques

| # | Key | Technique | Severity | Description |
|---|-----|-----------|----------|-------------|
| 1 | `response-mode` | Response Mode Escape | Critical | `redirect_uri` not validated across response modes — code delivered to attacker-controlled URI |
| 2 | `missing-state` | Missing State | Critical | No CSRF state issued or validated — login CSRF enables account takeover |
| 3 | `static-state` | Static State | Critical | Static state value shared across all sessions — replay in CSRF attack |
| 4 | `predictable-state` | Predictable State | Critical | State derived from timestamp — predictable, enabling CSRF |
| 5 | `pkce-plain` | S256->plain Downgrade | Critical | `plain` method accepted when `S256` registered — verifier exposed in transit |
| 6 | `no-verifier` | No Verifier Check | Critical | Token endpoint skips `code_verifier` validation entirely |
| 7 | `no-challenge` | No Challenge Required | Critical | PKCE not enforced at authorization — code issued without `code_challenge` |
| 8 | `confidential` | Confidential Client Downgrade | Critical | Confidential client exchanges code without verifier — PKCE bypassed |
| 9 | `aud-validation` | Missing aud Validation | Critical | Resource server doesn't validate JWT `aud` claim — cross-service token replay |
| 10 | `race` | OAuth Singleton Race | Critical | Shared singleton verifier state — concurrent requests enable cross-session code exchange |
| 11 | `prompt-none` | prompt=none Silent Redirect | Critical | `redirect_uri` not validated with `prompt=none` — silent code theft |
| 12 | `dcr` | Dynamic Client Registration | Medium | Registration endpoint exposed — rogue client registration possible |
| 13 | `mfa-bypass` | Grant Type -> MFA Bypass | Critical | Password grant bypasses browser-bound MFA entirely |
| 14 | `auth-method` | Auth Method Confusion | Critical | `private_key_jwt` registered but `client_secret_basic` accepted as fallback |
| 15 | `code-replay` | Code Replay | Critical | Authorization code reusable multiple times — no single-use enforcement |
| 16 | `scope-creep` | Scope Creep at Refresh | Critical | Refresh token issues broader scope than originally granted (RFC 6749 S6) |
| 17 | `resource` | Resource Indicator Omission | Critical | Resource indicator (RFC 8707) ignored — audience-unbound token issued |

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

### Generic scan against any OAuth server

```bash
# Auto-discovers endpoints via .well-known, probes all 17 techniques
python obreaker.py --target https://auth.example.com --all
```

### With credentials (enables password grant / MFA bypass testing)

```bash
python obreaker.py --target https://auth.example.com --all --credentials user:pass
```

### With pre-obtained auth code (enables full exploitation chains)

```bash
python obreaker.py --target https://auth.example.com --all --code AUTH_CODE --verifier CODE_VERIFIER
```

### With refresh token (enables scope creep testing)

```bash
python obreaker.py --target https://auth.example.com --all --refresh-token REFRESH_TOKEN
```

### Profile mode (for known vulnerable testbeds)

```bash
python obreaker.py --target https://403.brutelogic.net/authz/oauth --all --profile brutelogic
```

### Single technique

```bash
python obreaker.py --target https://auth.example.com --technique mfa-bypass --credentials user:pass
```

### Discovery mode (enumerate endpoints only)

```bash
python obreaker.py --target https://auth.example.com --discover
```

### JSON output

```bash
python obreaker.py --target https://auth.example.com --all --json results.json
```

### List available techniques

```bash
python obreaker.py --list
```

---

## How It Works

### Generic Mode (Default)

OBreaker probes the **standard OAuth endpoints** (`/authorize`, `/token`, `/register`) discovered via `.well-known/openid-configuration`. Each technique uses behavioral analysis to detect vulnerabilities:

1. **Authorization endpoint probing** — sends requests with missing/manipulated parameters (no `state`, no `code_challenge`, `plain` instead of `S256`, unregistered `redirect_uri`) and analyzes whether the server rejects or accepts them
2. **Token endpoint probing** — tests grant type acceptance (`password` grant), auth method fallbacks (Basic auth when `private_key_jwt` registered), code replay, scope escalation at refresh
3. **Registration probing** — checks if Dynamic Client Registration is open
4. **Full exploitation** — when `--code`, `--credentials`, or `--refresh-token` are provided, completes the full chain: code exchange, token theft, resource access, identity proof

Detection heuristics:
- Server returns **400/error mentioning the parameter** -> properly enforced, NOT vulnerable
- Server **accepts the request** (200/302) without the security parameter -> vulnerable
- Server rejects for **wrong credentials but accepts the grant type** -> grant type available (vulnerability)

### Profile Mode

For known vulnerable testbeds, profiles provide technique-specific endpoint mappings. Use `--profile brutelogic` for the BRuteLogic OAuth Testbed. Profiles can be added for any testbed.

### FFF Methodology

Every technique follows **Find -> Forge -> Fire**:

1. **Find** — Detect the vulnerability by probing the server's behavior
2. **Forge** — Craft the exploit: steal a code via unvalidated redirect, forge a PKCE bypass, submit a password grant to skip MFA
3. **Fire** — Complete the attack: exchange for a JWT, access protected resources, prove identity theft

---

## Output

### Terminal

Each finding shows the complete attack chain with color-coded phases:

```
[CRITICAL] Response Mode Escape [EXPLOITED]
  redirect_uri not validated across response modes

  ATTACK CHAIN:
    [FIND]  GET /authorize -> redirect_uri not validated
    [FORGE] Set redirect_uri=https://attacker.com/cb -> code stolen
    [FIRE]  POST /token with stolen code -> JWT obtained
    [FIRE]  GET /api with Bearer token -> protected resource accessed

  PROOF OF EXPLOITATION:
    Identity: user (user@example.com)
    Impact: Attacker steals authorization code via unvalidated redirect...
```

### JSON

The `--json` flag writes structured output with full attack chains and proof objects:

```json
[
  {
    "technique": "Response Mode Escape",
    "severity": "critical",
    "title": "Full account takeover via response_mode redirect bypass",
    "attack_chain": [
      {"phase": "FIND", "action": "...", "result": "...", "success": true},
      {"phase": "FORGE", "action": "...", "result": "..."},
      {"phase": "FIRE", "action": "...", "result": "..."}
    ],
    "proof": {
      "exploited": true,
      "identity_obtained": "user (user@example.com)",
      "jwt_claims": {"sub": "user", "iss": "...", "aud": "..."},
      "resource_accessed": true,
      "impact": "..."
    }
  }
]
```

---

## Options

| Flag | Description |
|------|-------------|
| `--target, -t` | OAuth base URL (required) |
| `--all, -a` | Run all 17 techniques |
| `--technique, -T` | Run single technique by key |
| `--profile, -p` | Use testbed-specific endpoint profile |
| `--client-id, -c` | OAuth client_id |
| `--client-secret` | OAuth client_secret |
| `--redirect-uri, -r` | OAuth redirect_uri |
| `--api-url` | Protected resource / userinfo endpoint |
| `--code` | Pre-obtained authorization code |
| `--verifier` | code_verifier for pre-obtained code |
| `--credentials` | `username:password` for password grant testing |
| `--refresh-token` | Refresh token for scope creep testing |
| `--json, -j` | Save JSON exploit report to file |
| `--verbose, -v` | Verbose output |
| `--discover, -d` | Only run endpoint discovery |
| `--list, -l` | List available technique keys |

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
- CVE-2024-22258 — PKCE bypass for confidential clients (Spring Security)
- CVE-2024-23647 — Auth method confusion (Authentik)
- CVE-2024-37893 — Redirect URI bypass (CAS)
- CVE-2024-48228 — PKCE not enforced
- CVE-2024-52289 — Regex redirect URI (Authentik)

### Tested Against
- [BRuteLogic OAuth Testbed](https://403.brutelogic.net/authz/oauth) (use `--profile brutelogic`)

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Only use it against applications you have explicit permission to test. The author is not responsible for misuse.

---

## License

MIT
