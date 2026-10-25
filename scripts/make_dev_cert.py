"""Create a self-signed TLS certificate for LOCAL DEMOS (free, no account, no internet).
    python scripts/make_dev_cert.py [hostname ...]          -> certs/dev.crt and certs/dev.key (valid 90 days)
Browsers will warn that the certificate is not trusted: that is expected for a self-signed certificate. For a trusted local certificate use the free
tool mkcert. For a real deployment use the bank's internal CA, or Let's Encrypt (free, public DNS name required): see README, "TLS"."""
from __future__ import annotations

import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make(names: list[str], out: Path, days: int = 90) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    sans = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    subj = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Coding-Agent Threat Monitor (demo)"), x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    out.mkdir(parents=True, exist_ok=True)
    crt, k = out / "dev.crt", out / "dev.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        k.chmod(0o600)
    except OSError:
        pass
    return crt, k


if __name__ == "__main__":
    names = sys.argv[1:] or ["localhost", "127.0.0.1"]
    crt, key = make(names, Path(__file__).resolve().parent.parent / "certs")
    print(f"wrote {crt} and {key} for {', '.join(names)} (valid 90 days)")
