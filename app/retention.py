"""Retention policy, tamper-evident archive and the compliance checks that go with them.

What is built:   a retention policy (hot / warm / total days, regulatory minimum, legal hold, residency regions) with checks that fail loudly
                 when the policy cannot meet the stated regulatory minimum; an archive writer that gzips, optionally encrypts (AES-256-GCM)
                 and signs (HMAC-SHA256) every batch and chains the batches in a manifest, so a removed, edited or re-ordered batch is detected.
What is an option (settings exist, needs a paid or external service, NOT exercised here): an S3 / S3-compatible backend with Object Lock
                 (WORM) and SSE-KMS. The adapter is written and unit-tested against a stub client only. Real S3, KMS and Glacier cost money and
                 need the bank's account: nothing in this prototype calls them.
What is not built: tier movement (hot to warm to cold), automatic expiry, restore workflows, a search layer over archived data. Production gets
                 those from the SIEM or data lake and from S3 lifecycle rules; this module documents what the bank must configure and checks it.
Rule: if encryption or signing is required and no key is available the archive REFUSES to write. It never falls back to plain text.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import netpolicy
from .config import BASE, OUT_DIR

PLATFORM_FILE = Path(os.environ.get("PLATFORM_CONFIG", BASE / "config" / "platform.json"))
GENESIS = "0" * 64


class ArchiveError(RuntimeError):
    pass


OVERRIDE: dict = {}     # approved changes made in the dashboard (dotted path -> value), set by app/retention_settings.py; the file stays the baseline


def _set_path(d: dict, path: str, value) -> None:
    keys = path.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def load_platform() -> dict:
    """config/platform.json (the baseline, changed by pull request) with approved dashboard changes laid over the retention section."""
    try:
        cfg = json.loads(PLATFORM_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    for path, value in list(OVERRIDE.items()):
        _set_path(cfg.setdefault("retention", {}), path, json.loads(json.dumps(value)))
    return cfg


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------------------------------------ keys
class Keys:
    """Archive keys come from the environment (ARCHIVE_ENC_KEY: 32 bytes, urlsafe base64; ARCHIVE_HMAC_KEY: any string of 32+ characters).
    ARCHIVE_KEYS=ephemeral creates throw-away keys in memory for a demo: the archive then cannot be decrypted after a restart, and says so."""

    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.ephemeral = False
        self.enc = self._enc(env.get("ARCHIVE_ENC_KEY", ""))
        raw = env.get("ARCHIVE_HMAC_KEY", "")
        self.mac = raw.encode() if len(raw) >= 32 else None
        if (self.enc is None or self.mac is None) and env.get("ARCHIVE_KEYS", "") == "ephemeral":
            self.ephemeral = True
            self.enc = self.enc or secrets.token_bytes(32)
            self.mac = self.mac or secrets.token_bytes(32)
            logging.warning("ARCHIVE_KEYS=ephemeral: archive keys exist only in memory (demo). Archives cannot be decrypted after a restart.")

    @staticmethod
    def _enc(v: str):
        if not v:
            return None
        try:
            k = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        except Exception:
            return None
        return k if len(k) == 32 else None


def genkey() -> dict:
    return {"ARCHIVE_ENC_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(), "ARCHIVE_HMAC_KEY": base64.urlsafe_b64encode(secrets.token_bytes(48)).decode()}


# ------------------------------------------------------------------------------------------------ policy
def tier_for_age(days: float, cfg: dict) -> str:
    r = cfg.get("retention", cfg)
    if days <= r.get("hot_days", 30):
        return "hot"
    if days <= r.get("warm_days", 90):
        return "warm"
    if days <= r.get("total_days", 365):
        return "cold"
    return "hold" if r.get("legal_hold") else "expire-eligible"


def checks(cfg: dict | None = None, keys: Keys | None = None) -> list[dict]:
    """Compliance checks on the retention settings. Each is pass / warn / fail with a plain reason. Nothing here is a legal opinion:
    the numbers are the owner's (Compliance); the checks only prove the settings are consistent with each other and with the stated minimum."""
    cfg = cfg or load_platform()
    r = cfg.get("retention", {})
    a = r.get("archive", {})
    s3 = a.get("s3", {})
    keys = keys or Keys()
    out = []

    def add(cid, title, status, detail):
        out.append({"id": cid, "title": title, "status": status, "detail": detail})

    hot, warm, total, mn, imm = (r.get(k, 0) for k in ("hot_days", "warm_days", "total_days", "regulatory_minimum_days", "immediate_access_days"))
    add("R1", "Total retention covers the regulatory minimum", "pass" if total >= mn > 0 else "fail",
        f"{total} days retained, minimum {mn} days ({r.get('status', 'assumed')} by {r.get('owner', 'owner')})")
    add("R2", "Recent data is searchable for the immediate-access window", "pass" if warm >= imm else "warn",
        f"hot {hot} days, hot plus warm {warm} days, immediate access required {imm} days")
    add("R3", "Tier boundaries are in order", "pass" if 0 < hot < warm < total else "fail", f"hot {hot} < warm {warm} < total {total}")
    add("R4", "Legal hold", "warn" if r.get("legal_hold") else "pass", "legal hold ON: nothing may expire" if r.get("legal_hold") else "off: data may expire after the total retention period")
    backend = a.get("backend", "local")
    if backend == "s3":
        lock_ok = s3.get("object_lock_mode") in ("COMPLIANCE", "GOVERNANCE") and s3.get("object_lock_days", 0) >= total
        add("R5", "Archive is immutable (WORM)", "pass" if s3.get("object_lock_mode") == "COMPLIANCE" and lock_ok else "warn" if lock_ok else "fail",
            f"Object Lock {s3.get('object_lock_mode')} for {s3.get('object_lock_days')} days (retention {total}). COMPLIANCE mode cannot be shortened by anyone, including the account owner")
        add("R6", "Archive encrypted at rest by the service", "pass" if s3.get("sse") == "aws:kms" and s3.get("kms_key_id") else "warn" if s3.get("sse") else "fail",
            f"SSE: {s3.get('sse') or 'none'}; KMS key: {'set' if s3.get('kms_key_id') else 'not set (service default key)'}")
        reg = s3.get("region", "")
        add("R7", "Data stays in the permitted regions", "pass" if reg in r.get("data_residency_regions", []) else "fail", f"region {reg}, permitted {', '.join(r.get('data_residency_regions', []))}")
        ep = netpolicy.check_url(s3.get("endpoint_url", "") or "https://s3.amazonaws.com", "S3 endpoint")
        add("R8", "Archive endpoint uses TLS", "pass" if ep["status"] == "ok" else "fail" if ep["status"] == "refused" else "warn", ep["detail"])
    else:
        add("R5", "Archive is immutable (WORM)", "warn", "local folder: tamper-EVIDENT (hash chain) but not tamper-PROOF. Production: S3 Object Lock in COMPLIANCE mode or equivalent WORM storage")
        if not a.get("encrypt"):
            add("R6", "Archive encrypted at rest", "fail", "encryption switched off: plain text on disk")
        elif keys.enc is None:
            add("R6", "Archive encrypted at rest", "fail", "encryption required but no ARCHIVE_ENC_KEY: the archive will refuse to write")
        else:
            add("R6", "Archive encrypted at rest", "warn" if keys.ephemeral else "pass", "AES-256-GCM per batch" + (", demo key kept in memory only (lost on restart)" if keys.ephemeral else ""))
        add("R7", "Data stays in the permitted regions", "warn", "local folder: residency is whatever host runs the container (on-premises or UAE region)")
        add("R8", "Archive endpoint uses TLS", "pass", "not applicable: local folder")
    add("R9", "Integrity: hash-chained manifest", "pass", "each batch records the SHA-256 of its stored bytes and of the previous record")
    if not a.get("sign"):
        add("R10", "Integrity: signed manifest (HMAC-SHA256)", "warn", "signing off: the chain proves order, not who wrote it")
    elif keys.mac is None:
        add("R10", "Integrity: signed manifest (HMAC-SHA256)", "fail", "signing required but no ARCHIVE_HMAC_KEY: the archive will refuse to write")
    else:
        add("R10", "Integrity: signed manifest (HMAC-SHA256)", "warn" if keys.ephemeral else "pass", "signed with ARCHIVE_HMAC_KEY" + (" (demo key, memory only)" if keys.ephemeral else ""))
    return out


# ------------------------------------------------------------------------------------------------ backends
class LocalBackend:
    kind = "local"

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def put(self, name: str, data: bytes, retain_until=None) -> dict:
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".part")
        tmp.write_bytes(data)
        os.replace(tmp, p)
        return {"backend": "local", "uri": f"archive/{name}"}

    def get(self, name: str) -> bytes:
        return (self.root / name).read_bytes()


class S3Backend:
    """Adapter for S3 or an S3-compatible store (e.g. MinIO). Unit-tested against a stub client only; not exercised against a real service here."""
    kind = "s3"

    def __init__(self, cfg: dict, client=None):
        self.cfg = cfg
        ep = netpolicy.check_url(cfg.get("endpoint_url", "") or "https://s3.amazonaws.com", "S3 endpoint")
        if ep["status"] == "refused":
            raise ArchiveError("S3 endpoint refused: " + ep["detail"])
        if client is None:
            try:
                import boto3   # optional, free library: pip install boto3. The S3 service itself is paid.
            except ImportError:
                raise ArchiveError("S3 backend selected but boto3 is not installed (pip install boto3). S3 and KMS are paid services: not enabled in this prototype.")
            client = boto3.client("s3", region_name=cfg.get("region") or None, endpoint_url=cfg.get("endpoint_url") or None)
        self.client = client

    def put(self, name: str, data: bytes, retain_until=None) -> dict:
        c = self.cfg
        kw = {"Bucket": c["bucket"], "Key": c.get("prefix", "") + name, "Body": data, "ChecksumAlgorithm": "SHA256"}
        if c.get("sse"):
            kw["ServerSideEncryption"] = c["sse"]
            if c.get("kms_key_id"):
                kw["SSEKMSKeyId"] = c["kms_key_id"]
        if c.get("object_lock_mode"):
            kw["ObjectLockMode"] = c["object_lock_mode"]
            kw["ObjectLockRetainUntilDate"] = retain_until or (datetime.now(timezone.utc) + timedelta(days=int(c.get("object_lock_days", 365))))
        self.client.put_object(**kw)
        return {"backend": "s3", "uri": f"s3://{c['bucket']}/{kw['Key']}", "object_lock": c.get("object_lock_mode"), "sse": c.get("sse")}

    def get(self, name: str) -> bytes:
        return self.client.get_object(Bucket=self.cfg["bucket"], Key=self.cfg.get("prefix", "") + name)["Body"].read()


# ------------------------------------------------------------------------------------------------ archive
class Archive:
    def __init__(self, root: Path | str | None = None, cfg: dict | None = None, keys: Keys | None = None, backend=None):
        self._fixed_cfg = cfg                    # None = follow the live settings, so an approved change applies at once
        base = Path(root or OUT_DIR)
        local = Path(self.a.get("local_path", "archive"))
        self.root = local if local.is_absolute() else base / local
        self.keys = keys or Keys()
        self._backend = backend
        self._injected = backend                 # a backend passed in (tests) is never replaced
        self._sig = ""
        self.manifest = self.root / "manifest.ndjson"
        self.state_file = self.root / "state.json"

    @property
    def cfg(self) -> dict:
        return self._fixed_cfg or load_platform()

    @property
    def r(self) -> dict:
        return self.cfg.get("retention", {})

    @property
    def a(self) -> dict:
        return self.r.get("archive", {})

    def backend(self):
        sig = json.dumps([self.a.get("backend"), self.a.get("s3", {})], sort_keys=True)
        if self._backend is None or (self._injected is None and sig != self._sig):
            self._backend = S3Backend(self.a.get("s3", {})) if self.a.get("backend") == "s3" else LocalBackend(self.root)
            self._sig = sig
        return self._backend

    # -------- state
    def _records(self) -> list[dict]:
        try:
            return [json.loads(l) for l in self.manifest.read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            return []

    def _state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"alerts": [], "audit_seq": 0}

    # -------- write
    def write_batch(self, kind: str, records: list[dict]) -> dict | None:
        if not records:
            return None
        if self.a.get("encrypt", True) and self.keys.enc is None:
            raise ArchiveError("encryption is required but no archive key is available (set ARCHIVE_ENC_KEY, or ARCHIVE_KEYS=ephemeral for a demo). Refusing to write plain text.")
        if self.a.get("sign", True) and self.keys.mac is None:
            raise ArchiveError("signing is required but no ARCHIVE_HMAC_KEY is available. Refusing to write an unsigned manifest.")
        be = self.backend()
        self.root.mkdir(parents=True, exist_ok=True)
        recs = self._records()
        seq = len(recs) + 1
        plain = ("\n".join(json.dumps(x, sort_keys=True, separators=(",", ":")) for x in records) + "\n").encode()
        blob = gzip.compress(plain, mtime=0)
        enc = bool(self.a.get("encrypt", True))
        if enc:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = secrets.token_bytes(12)
            blob = nonce + AESGCM(self.keys.enc).encrypt(nonce, blob, f"{kind}-{seq:06d}".encode())
        name = f"{datetime.now(timezone.utc):%Y/%m}/{kind}-{seq:06d}.ndjson.gz" + (".enc" if enc else "")
        retain = datetime.now(timezone.utc) + timedelta(days=int(self.a.get("s3", {}).get("object_lock_days", self.r.get("total_days", 365))))
        where = be.put(name, blob, retain)
        stamps = sorted(str(x.get("ts") or x.get("opened") or "") for x in records if x.get("ts") or x.get("opened"))
        rec = {"seq": seq, "kind": kind, "file": name, "records": len(records), "from": stamps[0] if stamps else None, "to": stamps[-1] if stamps else None,
               "stored_sha256": hashlib.sha256(blob).hexdigest(), "plain_sha256": hashlib.sha256(plain).hexdigest(), "encrypted": enc,
               "created": _now(), "storage": where, "prev": recs[-1]["hash"] if recs else GENESIS}
        rec["hash"] = hashlib.sha256(json.dumps({k: rec[k] for k in sorted(rec)}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if self.a.get("sign", True):
            rec["mac"] = hmac.new(self.keys.mac, rec["hash"].encode(), hashlib.sha256).hexdigest()
        with open(self.manifest, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        if isinstance(be, S3Backend):                 # the manifest record is also stored immutably, one object per record
            be.put(f"manifest/{seq:06d}.json", json.dumps(rec).encode(), retain)
        return rec

    def archive_now(self, alerts: list[dict], audit_records: list[dict], cases: list[dict]) -> dict:
        st = self._state()
        done = set(st["alerts"])
        new_alerts = [a for a in alerts if a["alert_id"] not in done]
        new_audit = [r for r in audit_records if r.get("seq", 0) > st["audit_seq"]]
        out = []
        for kind, rows in (("alerts", new_alerts), ("audit", new_audit), ("cases", [{k: v for k, v in c.items() if k != "history"} for c in cases] if new_alerts else [])):
            r = self.write_batch(kind, rows)
            if r:
                out.append({k: r[k] for k in ("seq", "kind", "file", "records", "encrypted", "stored_sha256")})
        if new_alerts or new_audit:
            st["alerts"] = sorted(done | {a["alert_id"] for a in new_alerts})
            st["audit_seq"] = max([st["audit_seq"]] + [r.get("seq", 0) for r in new_audit])
            self.root.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps(st), encoding="utf-8")
        return {"batches": out, "nothing_new": not out}

    # -------- verify / read
    def verify(self) -> dict:
        recs = self._records()
        prev = GENESIS
        for r in recs:
            body = {k: v for k, v in r.items() if k not in ("hash", "mac")}
            if r.get("prev") != prev:
                return {"ok": False, "records": len(recs), "broken_at": r["seq"], "reason": "chain broken: a batch was removed, re-ordered or inserted"}
            if hashlib.sha256(json.dumps({k: body[k] for k in sorted(body)}, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != r.get("hash"):
                return {"ok": False, "records": len(recs), "broken_at": r["seq"], "reason": "manifest record was edited"}
            if "mac" in r:
                if self.keys.mac is None:
                    return {"ok": False, "records": len(recs), "broken_at": r["seq"], "reason": "signed manifest but no ARCHIVE_HMAC_KEY to check it"}
                if not hmac.compare_digest(r["mac"], hmac.new(self.keys.mac, r["hash"].encode(), hashlib.sha256).hexdigest()):
                    return {"ok": False, "records": len(recs), "broken_at": r["seq"], "reason": "signature does not match: wrong key or forged record"}
            if r["storage"]["backend"] == "local":
                try:
                    data = (self.root / r["file"]).read_bytes()
                except OSError:
                    return {"ok": False, "records": len(recs), "broken_at": r["seq"], "reason": f"batch file missing: {r['file']}"}
                if hashlib.sha256(data).hexdigest() != r["stored_sha256"]:
                    return {"ok": False, "records": len(recs), "broken_at": r["seq"], "reason": f"batch file changed after it was written: {r['file']}"}
            prev = r["hash"]
        remote = sum(r["storage"]["backend"] != "local" for r in recs)
        return {"ok": True, "records": len(recs), "head": prev, "remote_batches_not_rechecked": remote,
                "note": "Hashes, chain and signatures checked." + (f" {remote} batch(es) are in remote storage: verify them with the provider's checksum / Object Lock report." if remote else "")}

    def read_batch(self, seq: int) -> list[dict]:
        r = next((x for x in self._records() if x["seq"] == seq), None)
        if not r:
            raise ArchiveError("no such batch")
        data = self.backend().get(r["file"])
        if r["encrypted"]:
            if self.keys.enc is None:
                raise ArchiveError("batch is encrypted and no ARCHIVE_ENC_KEY is available (demo keys are lost on restart)")
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            data = AESGCM(self.keys.enc).decrypt(data[:12], data[12:], f"{r['kind']}-{r['seq']:06d}".encode())
        return [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l.strip()]

    def view(self) -> dict:
        recs = self._records()
        return {"batches": [{k: r[k] for k in ("seq", "kind", "file", "records", "from", "to", "encrypted", "created", "stored_sha256")} | {"signed": "mac" in r, "where": r["storage"]["uri"]} for r in recs[-30:][::-1]],
                "total_batches": len(recs), "records": sum(r["records"] for r in recs)}


def policy_view(archive: Archive | None = None) -> dict:
    cfg = load_platform()
    r = cfg.get("retention", {})
    arch = archive or Archive(cfg=cfg)
    chk = checks(cfg, arch.keys)
    return {"policy": {k: r.get(k) for k in ("status", "owner", "source", "regulatory_minimum_days", "immediate_access_days", "hot_days", "warm_days", "total_days", "legal_hold", "data_residency_regions")},
            "archive": {"backend": r.get("archive", {}).get("backend"), "encrypt": r.get("archive", {}).get("encrypt"), "sign": r.get("archive", {}).get("sign"),
                        "keys": "ephemeral demo keys (memory only)" if arch.keys.ephemeral else "from environment" if arch.keys.enc is not None else "none", "s3": {k: v for k, v in r.get("archive", {}).get("s3", {}).items()}},
            "tiers": [{"tier": "hot", "range": f"0 to {r.get('hot_days')} days", "purpose": "fast search for analysts (production: the SIEM index)"},
                      {"tier": "warm", "range": f"{r.get('hot_days')} to {r.get('warm_days')} days", "purpose": "searchable, slower and cheaper"},
                      {"tier": "cold", "range": f"{r.get('warm_days')} to {r.get('total_days')} days", "purpose": "immutable archive for audit and regulators (this module)"},
                      {"tier": "expire", "range": f"after {r.get('total_days')} days", "purpose": "eligible for deletion unless a legal hold is set (never automatic here)"}],
            "checks": chk, "summary": {s: sum(c["status"] == s for c in chk) for s in ("pass", "warn", "fail")}, "archive_state": arch.view(),
            "cost_note": "The prototype uses a local folder or a free local MinIO. S3, KMS, Object Lock storage and Glacier are paid AWS services: they need your approval and the bank's account before anything is switched on."}


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "genkey":
        for k, v in genkey().items():
            print(f"{k}={v}")
        print("# store these in the bank's secret manager, never in git or in this file", file=sys.stderr)
        return 0
    a = Archive()
    if cmd == "verify":
        print(json.dumps(a.verify(), indent=1))
        return 0 if a.verify()["ok"] else 1
    chk = checks(keys=a.keys)
    for c in chk:
        print(f"{c['status'].upper():5} {c['id']:4} {c['title']}: {c['detail']}")
    return 1 if any(c["status"] == "fail" for c in chk) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
