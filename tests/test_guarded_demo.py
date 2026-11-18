"""cosign demo --guarded against the fake devnet. No network."""

import json

import pytest

pytest.importorskip("solders")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from test_solana_ledger import FakeDevnet  # noqa: E402

from cosign import cli  # noqa: E402
from cosign.attacks import ATTACKER  # noqa: E402
from cosign.demo import AGENT, COSIGNER, local_policy_row, run_guarded_demo  # noqa: E402
from cosign.solana_ledger import KeyStore, SolanaLedger  # noqa: E402


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COSIGN_KEYPAIRS", str(tmp_path / "keys.json"))
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(tmp_path / "issuer.json"))
    net = FakeDevnet()
    ledger = SolanaLedger(net, KeyStore(), poll=0)
    net.lamports[str(ledger.pubkey(AGENT))] = 5 * 10 ** 9
    net.mint_to(ledger, "operator", 40)
    return net, ledger, tmp_path


def demo(ledger, **kw):
    lines = []
    code = run_guarded_demo(ledger, treasury="operator", out=lines.append,
                            issuer_key=Ed25519PrivateKey.generate(), **kw)
    return code, "\n".join(lines)


def test_unguarded_wallet_is_robbed_and_the_vault_refuses(world):
    net, ledger, tmp = world
    code, out = demo(ledger)
    assert code == 0, out
    vault = ledger.multisig_vault(AGENT)
    assert vault["m"] == 2 and str(ledger.pubkey(COSIGNER)) in vault["signers"]
    assert "poisoned page asks for 2.5 USDC" in out

    assert f"1) single-signer wallet {ledger.pubkey(AGENT)}: attacker got 2.5 USDC" in out
    assert f"2) guarded vault {vault['token_account']}: attacker got 0 USDC, task done True" in out
    assert (f"REFUSED 2.5 USDC -> {ATTACKER}: untrusted input was read this episode (browse, token_info) "
            f"and recipient {ATTACKER} is not on the allowlist") in out
    assert "cosigned 1 USDC agent_wallet -> dex_pool" in out
    # vault create + 2 top-ups + run 1 (theft + swap) + run 2 (swap)
    assert out.count("explorer.solana.com/tx/") == 6
    assert ledger.balance(ATTACKER) == 2.5                          # only from the single-signer wallet
    assert ledger.multisig_vault(AGENT)["balance"] == 9 and ledger.balance("dex_pool") == 2

    log = [json.loads(l) for l in (tmp / "logs" / "guard.log").read_text().splitlines()]
    assert [l["decision"] for l in log] == ["refuse", "approve"]


def test_second_run_reuses_the_vault_and_skips_top_ups(world):
    net, ledger, _ = world
    demo(ledger)
    net.mint_to(ledger, AGENT, 5)
    net.mint_to(ledger, ledger.multisig_name(AGENT), 5)
    code, out = demo(ledger)
    assert code == 0, out
    assert "created:" not in out and "topped up" not in out


def test_needs_sol_and_treasury_usdc(world):
    net, ledger, _ = world
    with pytest.raises(SystemExit, match="--treasury"):
        run_guarded_demo(ledger, treasury="empty", out=lambda s: None, issuer_key=Ed25519PrivateKey.generate())
    net.lamports.clear()
    with pytest.raises(SystemExit, match="SOL"):
        demo(ledger)


def test_remote_guard_url(world, monkeypatch):
    net, ledger, _ = world
    seen = []
    monkeypatch.setattr("cosign.solana_ledger.http_guard", lambda url: lambda req: seen.append(req) or
                        {"decision": "refuse", "reason": "remote says no"})
    code, out = demo(ledger, guard_url="http://127.0.0.1:8100")
    assert code == 1                                                 # the swap was refused too
    assert "REFUSED 2.5 USDC" in out and "REFUSED 1 USDC" in out and "remote says no" in out
    assert {r["run_id"] for r in seen} == {"naive/recommended"}


def test_local_policy_is_a_full_strength_recommended_run():
    row = local_policy_row()
    assert row["run"] == "naive/recommended" and row["limit"] == 5000 and row["trials"] == 3


def test_cli_demo_guarded_needs_no_websocket(world, monkeypatch):
    net, ledger, _ = world
    monkeypatch.delenv("QUICKNODE_WSS_URL", raising=False)
    monkeypatch.setattr("cosign.solana_ledger.SolanaLedger.from_env", classmethod(lambda cls: ledger))
    got = {}
    monkeypatch.setattr("cosign.demo.run_guarded_demo", lambda lg, **kw: got.update(kw) or 0)
    assert cli.main(["demo", "--guarded", "--treasury", "operator"]) == 0
    assert got["treasury"] == "operator" and got["cosigner"] == "cosigner" and got["guard_url"] is None
