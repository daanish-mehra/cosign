"""Signed scores: an ed25519-signed statement of an agent's crash-test score and spend limit.

Envelope: {"alg": "ed25519", "public_key": <b64>, "signature": <b64>, "payload": {...}}
The signature covers the payload as canonical JSON (sorted keys, no spaces). Payload:
    agent, agent_id, guards, score, limit, test_strength, issued_at, expires_at (7 days), agent_hash
`limit` is the earned limit after the test-strength cap (see grant.effective_limit).
`agent_hash` pins the exact configuration tested: model spec, guards, system prompt and tool specs.

The signing key is kept outside the repo, default ~/.config/cosign/attest-ed25519.json (0600),
override with COSIGN_ATTEST_KEY.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .attacks import MUTATIONS

VALID_FOR = timedelta(days=7)
DEFAULT_KEY = Path("~/.config/cosign/attest-ed25519.json")
PRESETS = ("none", "caps", "quarantine", "recommended")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# --- identity --------------------------------------------------------------------
def preset_of(row: dict) -> str:
    if row.get("preset"):
        return row["preset"]
    from .cli import guard_preset
    for name in PRESETS:
        if guard_preset(name).enabled() == list(row.get("guards") or []):
            return name
    return "custom-" + hashlib.sha256(canonical(row.get("guards"))).hexdigest()[:6]


def agent_id(row: dict) -> str:
    """URL-safe id for an (agent, guard preset) pair, e.g. openai-meta-llama-llama-3-1-8b-instruct--recommended."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(row["agent"]).lower()).strip("-")
    return f"{slug}--{preset_of(row)}"


def agent_hash(agent: str, guards: list[str]) -> str:
    from .agent import SYSTEM, TOOL_SPECS
    spec = {"agent": agent, "guards": sorted(guards or []), "system": SYSTEM, "tools": TOOL_SPECS}
    return "sha256:" + hashlib.sha256(canonical(spec)).hexdigest()


# --- key -------------------------------------------------------------------------
def key_path() -> Path:
    return Path(os.environ.get("COSIGN_ATTEST_KEY") or DEFAULT_KEY).expanduser()


def load_key(create: bool = True):
    """The issuer's Ed25519PrivateKey; created (0600, in a 0700 folder) on first use."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = key_path()
    if path.exists():
        seed = base64.b64decode(json.loads(path.read_text())["seed"])
        return Ed25519PrivateKey.from_private_bytes(seed)
    if not create:
        return None
    key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization as s
    seed = key.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"alg": "ed25519", "seed": b64(seed)}, f)
    return key


def public_key_b64(key) -> str:
    from cryptography.hazmat.primitives import serialization as s
    return b64(key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))


# --- sign / verify ---------------------------------------------------------------
def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def sign(payload: dict, key=None) -> dict:
    key = key or load_key()
    return {"alg": "ed25519", "public_key": public_key_b64(key),
            "signature": b64(key.sign(canonical(payload))), "payload": payload}


def attestation_payload(row: dict, now: datetime | None = None) -> dict:
    from .grant import effective_limit
    now = now or datetime.now(timezone.utc)
    limit, notes = effective_limit(row)
    trials, muts = row.get("trials"), row.get("mutations")
    return {
        "agent": row["agent"], "agent_id": agent_id(row), "guards": list(row.get("guards") or []),
        "score": row["score"], "limit": limit,
        "test_strength": {"trials": trials, "mutations": muts, "max_mutations": len(MUTATIONS),
                          "full": bool(trials and trials >= 3 and muts == len(MUTATIONS)), "notes": notes},
        "issued_at": _iso(now), "expires_at": _iso(now + VALID_FOR),
        "agent_hash": agent_hash(row["agent"], list(row.get("guards") or [])),
    }


def attest(row: dict, key=None, now: datetime | None = None) -> dict:
    return sign(attestation_payload(row, now), key)


def verify(env: dict, trusted: str | None = None, now: datetime | None = None) -> tuple[bool, str]:
    """(ok, reason). Checks algorithm, signature, issuer (if `trusted` public key given) and validity window."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        if env.get("alg") != "ed25519":
            return False, f"unsupported alg {env.get('alg')!r}"
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(env["public_key"]))
        pub.verify(base64.b64decode(env["signature"]), canonical(env["payload"]))
    except InvalidSignature:
        return False, "bad signature: payload was changed or signed by another key"
    except (KeyError, TypeError, ValueError) as e:
        return False, f"malformed attestation: {e}"
    if trusted is not None and env["public_key"] != trusted:
        return False, "signed by an untrusted key"
    now = now or datetime.now(timezone.utc)
    p = env["payload"]
    try:
        issued, expires = _parse(p["issued_at"]), _parse(p["expires_at"])
    except (KeyError, ValueError) as e:
        return False, f"malformed validity window: {e}"
    if now < issued - timedelta(minutes=5):
        return False, "issued in the future"
    if now >= expires:
        return False, f"expired at {p['expires_at']}"
    return True, "valid" if trusted is not None else "valid signature (issuer not checked: no trusted key given)"
