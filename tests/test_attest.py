import json
from datetime import datetime, timedelta, timezone

import pytest

from cosign import cli
from cosign.attest import agent_hash, agent_id, attest, load_key, public_key_b64, verify


@pytest.fixture(autouse=True)
def key_file(tmp_path, monkeypatch):
    path = tmp_path / "cfg" / "attest.json"
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(path))
    return path


ROW = {"agent": "openai:meta-llama/llama-3.1-8b-instruct", "preset": "recommended",
       "guards": ["allowlist", "max_per_tx=25"], "score": 92, "limit": 5000, "trials": 3, "mutations": 6,
       "utility_under_attack": 0.9}


def test_attestation_fields_and_round_trip(key_file):
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    env = attest(ROW, now=now)
    p = env["payload"]
    assert {"agent", "guards", "score", "limit", "test_strength", "issued_at", "expires_at", "agent_hash"} <= set(p)
    assert p["agent_id"] == "openai-meta-llama-llama-3-1-8b-instruct--recommended"
    assert p["limit"] == 5000 and p["test_strength"]["full"] is True
    assert p["expires_at"] == "2026-11-25T00:00:00Z"
    assert key_file.stat().st_mode & 0o777 == 0o600 and key_file.parent.stat().st_mode & 0o777 == 0o700

    trusted = public_key_b64(load_key())
    assert verify(env, trusted, now=now + timedelta(days=1)) == (True, "valid")
    assert verify(env, trusted, now=now + timedelta(days=7))[1].startswith("expired")


def test_tampering_wrong_issuer_and_weak_tests():
    env = attest(ROW)
    trusted = public_key_b64(load_key())
    forged = json.loads(json.dumps(env)); forged["payload"]["limit"] = 9999
    assert verify(forged, trusted) == (False, "bad signature: payload was changed or signed by another key")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = attest(ROW, key=Ed25519PrivateKey.generate())
    assert verify(other, trusted) == (False, "signed by an untrusted key")
    assert verify({"alg": "rsa"}, trusted)[0] is False

    weak = attest({**ROW, "mutations": None})["payload"]
    assert weak["limit"] == 250 and weak["test_strength"]["full"] is False
    assert agent_hash("a", ["x", "y"]) == agent_hash("a", ["y", "x"]) != agent_hash("b", ["x", "y"])


def test_preset_inferred_for_old_rows():
    assert agent_id({"agent": "naive", "guards": ["none"]}) == "naive--none"
    assert agent_id({"agent": "naive", "guards": ["z"]}).startswith("naive--custom-")


def test_cli_attest_and_verify(tmp_path, capsys):
    results = tmp_path / "results.json"
    results.write_text(json.dumps([ROW]))
    assert cli.main(["attest", "--results", str(results), "--run", "0"]) == 0
    out = tmp_path / "attestation-0.json"
    assert cli.main(["verify", str(out)]) == 0 and "OK: valid" in capsys.readouterr().out

    env = json.loads(out.read_text()); env["payload"]["score"] = 100
    out.write_text(json.dumps(env))
    assert cli.main(["verify", str(out)]) == 1 and "INVALID" in capsys.readouterr().out


def test_cli_verify_with_explicit_pubkey(tmp_path, capsys):
    results = tmp_path / "results.json"
    results.write_text(json.dumps([ROW]))
    out = tmp_path / "a.json"
    cli.main(["attest", "--results", str(results), "--run", "0", "--out", str(out)])
    pub = json.loads(out.read_text())["public_key"]
    assert cli.main(["verify", str(out), "--pubkey", pub]) == 0
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = public_key_b64(Ed25519PrivateKey.generate())
    assert cli.main(["verify", str(out), "--pubkey", other]) == 1
    assert "untrusted key" in capsys.readouterr().out


def test_cli_verify_without_any_key_fails_closed(tmp_path, monkeypatch):
    env = tmp_path / "a.json"
    env.write_text(json.dumps(attest(ROW)))
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(tmp_path / "missing.json"))
    with pytest.raises(SystemExit, match="no trusted key"):
        cli.main(["verify", str(env)])


def test_key_file_never_printed(tmp_path, capsys, key_file):
    results = tmp_path / "results.json"
    results.write_text(json.dumps([ROW]))
    cli.main(["attest", "--results", str(results), "--run", "0"])
    seed = json.loads(key_file.read_text())["seed"]
    assert seed not in capsys.readouterr().out
    assert seed not in (tmp_path / "attestation-0.json").read_text()
