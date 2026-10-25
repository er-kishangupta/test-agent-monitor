"""No plain text on the wire. Every outbound or inbound endpoint the monitor is configured with is checked here.

Rule: an http:// endpoint is refused unless it is loopback / the built-in mock, or ALLOW_INSECURE=1 is set (the demo does this explicitly and the
dashboard shows a warning for each exception). TLS is configured at start-up (app/serve.py); REQUIRE_TLS=1 refuses plain-HTTP requests."""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def allow_insecure() -> bool:
    return os.environ.get("ALLOW_INSECURE", "") == "1"


def check_url(url: str, purpose: str) -> dict:
    """Returns {purpose, url, scheme, status: ok|warn|refused|mock|unset, detail}. 'refused' means the caller must not use the endpoint."""
    u = (url or "").strip()
    if not u:
        return {"purpose": purpose, "url": "", "scheme": "", "status": "unset", "detail": "not configured"}
    if u == "mock":
        return {"purpose": purpose, "url": "mock", "scheme": "", "status": "mock", "detail": "built-in mock, nothing leaves the process"}
    p = urlparse(u)
    host = (p.hostname or "").lower()
    if p.scheme == "https":
        return {"purpose": purpose, "url": u, "scheme": "https", "status": "ok", "detail": "TLS"}
    if p.scheme != "http":
        return {"purpose": purpose, "url": u, "scheme": p.scheme, "status": "refused", "detail": "unsupported scheme"}
    loop = host in LOOPBACK
    try:
        loop = loop or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if loop:
        return {"purpose": purpose, "url": u, "scheme": "http", "status": "warn", "detail": "plain HTTP to loopback only (never leaves this machine)"}
    if allow_insecure():
        return {"purpose": purpose, "url": u, "scheme": "http", "status": "warn", "detail": "plain HTTP allowed by ALLOW_INSECURE=1 (demo only)"}
    return {"purpose": purpose, "url": u, "scheme": "http", "status": "refused", "detail": "plain HTTP refused: use https:// (or set ALLOW_INSECURE=1 for a demo)"}


def usable(url: str, purpose: str = "") -> bool:
    return check_url(url, purpose)["status"] in ("ok", "warn", "mock")


def tls_status() -> dict:
    cert, key = os.environ.get("TLS_CERT_FILE", ""), os.environ.get("TLS_KEY_FILE", "")
    return {"serving_tls": bool(cert and key and os.path.exists(cert) and os.path.exists(key)), "cert_file": cert, "require_tls": os.environ.get("REQUIRE_TLS", "") == "1",
            "behind_tls_proxy": os.environ.get("TLS_TERMINATED_UPSTREAM", "") == "1"}
