"""cosign doctor with fake RPC/WSS/HTTP: no network, no keys created, secrets never printed."""

import json
import os

from cosign import cli, doctor
from cosign.doctor import b58encode, read_keypairs, render, run_checks
from cosign.solana_ledger import DEVNET_GENESIS, DEVNET_USDC

SECRET = "sk-ant-THIS-MUST-NOT-PRINT"
WSS = "wss://abc.solana-devnet.quiknode.pro/TOKEN-MUST-NOT-PRINT/"
RPC = "https://abc.solana-devnet.quiknode.pro/TOKEN-MUST-NOT-PRINT/"
TREASURY_PK, AGENT_PK = bytes(range(1, 33)), bytes(range(101, 133))


def b58decode(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in s:
        n = n * 58 + alphabet.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def keyfile(tmp_path, names=("treasury", "agent_wallet"), mode=0o600):
    pks = {"treasury": TREASURY_PK, "agent_wallet": AGENT_PK, "attacker_wallet": bytes(32)}
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({n: list(bytes(32) + pks[n]) for n in names}))
    os.chmod(path, mode)
    return path


def fake_rpc(genesis=DEVNET_GENESIS, sol=None, usdc=None, fail=False):
    sol = sol or {}
    usdc = usdc or {}

    def rpc(method, params):
        if fail:
            raise OSError("down")
        if method == "getGenesisHash":
            return genesis
        if method == "getBalance":
            return {"value": int(sol.get(params[0], 0) * 1e9)}
        if method == "getTokenAccountsByOwner":
            assert params[1] == {"mint": DEVNET_USDC}
            amt = usdc.get(params[0])
            return {"value": [] if amt is None else [
                {"account": {"data": {"parsed": {"info": {"tokenAmount": {"uiAmountString": str(amt)}}}}}}]}
        raise AssertionError(method)
    return lambda url: rpc


def by_name(checks):
    return {c.name: c for c in checks}


def test_base58_and_keypairs_are_read_without_creating(tmp_path):
    assert b58encode(bytes(32)) == "1" * 32
    sol_mint = "So11111111111111111111111111111111111111112"
    assert b58encode(b58decode(sol_mint)) == sol_mint
    path = keyfile(tmp_path)
    before = path.read_text()
    keys = read_keypairs(path)
    assert keys == {"treasury": b58encode(TREASURY_PK), "agent_wallet": b58encode(AGENT_PK)}
    assert path.read_text() == before and len(list(tmp_path.iterdir())) == 1


def test_all_green(tmp_path):
    t, a = b58encode(TREASURY_PK), b58encode(AGENT_PK)
    env = {"ANTHROPIC_API_KEY": SECRET, "QUICKNODE_WSS_URL": WSS, "SOLANA_RPC_URL": RPC,
           "COSIGN_KEYPAIRS": str(keyfile(tmp_path))}
    seen = []
    checks = run_checks(env, fake_rpc(sol={t: 2, a: 0.05}, usdc={t: 500, a: 3}),
                        ws=seen.append, http=lambda url: 200, guard_url="http://127.0.0.1:8100/healthz")
    assert seen == [WSS]
    assert not [c for c in checks if c.ok is False], render(checks)
    c = by_name(checks)
    assert c["treasury USDC"].detail == "500 USDC" and c["agent_wallet SOL"].detail == "0.05 SOL"
    assert c["guard self-test"].ok and c["guard service http://127.0.0.1"].ok
    out = render(checks)
    assert out.endswith(f"{sum(x.ok is True for x in checks)} passed, 0 failed, "
                        f"{sum(x.ok is None for x in checks)} skipped")
    assert SECRET not in out and "TOKEN-MUST-NOT-PRINT" not in out
    assert "RPC https://abc.solana-devnet.quiknode.pro" in out and "fix:" not in out


def test_failures_come_with_fixes_and_never_print_secrets(tmp_path):
    t, a = b58encode(TREASURY_PK), b58encode(AGENT_PK)
    env = {"OPENAI_API_KEY": SECRET, "QUICKNODE_WSS_URL": WSS,
           "COSIGN_KEYPAIRS": str(keyfile(tmp_path, mode=0o644))}

    def ws_down(url):
        raise TimeoutError

    checks = run_checks(env, fake_rpc(sol={t: 0, a: 0}, usdc={t: 0}), ws=ws_down,
                        http=lambda url: 503, guard_url="http://guard.local/")
    failed = {c.name for c in checks if c.ok is False}
    assert failed == {"keypair file", "WSS wss://abc.solana-devnet.quiknode.pro",
                      "treasury SOL", "treasury USDC", "agent_wallet SOL", "guard service http://guard.local"}
    assert all(c.fix for c in checks if c.ok is False)
    out = render(checks)
    assert "fix: chmod 600" in out and "faucet.solana.com" in out and "faucet.circle.com" in out
    assert t in out                                    # public keys are fine to show, so the fix is actionable
    assert SECRET not in out and "TOKEN-MUST-NOT-PRINT" not in out
    assert by_name(checks)["LLM API key"].detail == "set: OPENAI_API_KEY"


def test_nothing_configured(tmp_path):
    env = {"COSIGN_KEYPAIRS": str(tmp_path / "nope.json")}
    checks = run_checks(env, fake_rpc(fail=True), ws=lambda u: None, http=lambda u: 200)
    c = by_name(checks)
    assert c["LLM API key"].ok is False and c["QUICKNODE_WSS_URL"].ok is False
    assert c["RPC https://api.devnet.solana.com"].ok is False and c["WSS endpoint"].ok is None
    assert c["keypair file"].ok is False and c["keypair file"].detail.endswith("nope.json missing")
    assert c["devnet balances"].ok is None and c["guard service"].ok is None
    assert c["guard self-test"].ok is True
    assert not (tmp_path / "nope.json").exists()       # doctor never creates keypairs


def test_wrong_cluster_and_missing_agent_key(tmp_path):
    env = {"COSIGN_KEYPAIRS": str(keyfile(tmp_path, names=("treasury",)))}
    checks = run_checks(env, fake_rpc(genesis="mainnet-genesis"), ws=lambda u: None, http=lambda u: 200)
    c = by_name(checks)
    assert c["RPC https://api.devnet.solana.com"].detail == "reachable but not devnet"
    assert c["keypair agent_wallet"].ok is False and c["keypair treasury"].ok is True


def test_cli_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_checks", lambda guard_url=None: [doctor.Check("x", True, "ok")])
    assert cli.main(["doctor"]) == 0 and "1 passed, 0 failed" in capsys.readouterr().out
    monkeypatch.setattr(doctor, "run_checks", lambda guard_url=None: [doctor.Check("x", False, "bad", "do y")])
    assert cli.main(["doctor", "--guard-url", "http://x"]) == 1 and "fix: do y" in capsys.readouterr().out
