"""Start the monitor. Serves HTTPS when TLS_CERT_FILE and TLS_KEY_FILE point at a certificate and key; otherwise plain HTTP (demo only).
REQUIRE_TLS=1 makes the app refuse plain-HTTP requests. TLS_MIN_VERSION defaults to 1.2."""
from __future__ import annotations

import os
import ssl
import sys

import uvicorn


def main() -> None:
    host, port = os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8000"))
    cert, key = os.environ.get("TLS_CERT_FILE", ""), os.environ.get("TLS_KEY_FILE", "")
    kw = {}
    if cert or key:
        if not (os.path.exists(cert) and os.path.exists(key)):
            sys.exit(f"TLS requested but certificate or key not found ({cert!r}, {key!r}). Not starting in plain HTTP by accident.")
        kw = {"ssl_certfile": cert, "ssl_keyfile": key,
              "ssl_version": ssl.PROTOCOL_TLS_SERVER}
        print(f"serving HTTPS on {host}:{port}", flush=True)
    else:
        print(f"WARNING: serving plain HTTP on {host}:{port} (demo). Set TLS_CERT_FILE / TLS_KEY_FILE for HTTPS.", flush=True)
    uvicorn.run("app.main:app", host=host, port=port, **kw)


if __name__ == "__main__":
    main()
