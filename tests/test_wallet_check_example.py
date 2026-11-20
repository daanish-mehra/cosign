"""examples/wallet_check.py signs the legit swap and refuses the theft, the loose swap and the unlimited approval."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from test_check import row  # noqa: E402

from cosign.attest import agent_id, public_key_b64  # noqa: E402
from cosign.policy import signed_limit  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "wallet_check.py"


def run(*args):
    return subprocess.run([sys.executable, str(EXAMPLE), *args], capture_output=True, text=True, timeout=60)


def test_demo_wallet_with_a_local_attestation(tmp_path):
    key = Ed25519PrivateKey.generate()
    r = row()
    (tmp_path / "limit.json").write_text(json.dumps(signed_limit(r, key)))
    p = run("--agent", agent_id(r), "--attestation", str(tmp_path / "limit.json"), "--trusted-key", public_key_b64(key))
    assert p.returncode == 0, p.stderr
    lines = p.stdout.splitlines()
    assert [ln.split()[0] for ln in lines] == ["SIGN", "REFUSE", "REFUSE", "REFUSE"]
    assert lines[0].endswith("5 USDC swap to dex_pool within policy")
    assert "attacker_wallet is not on the allowlist" in lines[1]
    assert "slippage 5000 bps" in lines[2] and "unlimited USDC at risk (approve)" in lines[3]
    assert len(EXAMPLE.read_text().splitlines()) <= 30


def test_demo_wallet_refuses_everything_without_a_trusted_attestation(tmp_path):
    r = row()
    (tmp_path / "limit.json").write_text(json.dumps(signed_limit(r, Ed25519PrivateKey.generate())))
    other = public_key_b64(Ed25519PrivateKey.generate())
    p = run("--agent", agent_id(r), "--attestation", str(tmp_path / "limit.json"), "--trusted-key", other)
    assert p.returncode == 0 and all(ln.startswith("REFUSE") and "untrusted key" in ln for ln in p.stdout.splitlines())
    p = run("--agent", agent_id(r), "--api", "http://127.0.0.1:9")          # nothing listening: fail closed
    assert p.returncode == 0 and all(ln.startswith("REFUSE") for ln in p.stdout.splitlines())
