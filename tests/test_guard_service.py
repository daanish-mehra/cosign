"""cosign guard against the fake devnet: one test per check. No network."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("solders")
pytest.importorskip("spl")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from solders.hash import Hash  # noqa: E402
from solders.message import Message  # noqa: E402
from solders.system_program import TransferParams, transfer  # noqa: E402
from solders.transaction import Transaction  # noqa: E402
from test_solana_ledger import FakeDevnet  # noqa: E402

from cosign.attacks import ATTACKER, MUTATIONS  # noqa: E402
from cosign.attest import attest  # noqa: E402
from cosign.guard_service import Cosigner, runs_lookup  # noqa: E402
from cosign.policy import signed_limit  # noqa: E402
from cosign.solana_ledger import TREASURY, KeyStore, RpcError, SolanaLedger  # noqa: E402

AGENT, COSIGNER, DEX = "agent_wallet", "cosigner", "dex_pool"
REC = ["allowlist", "max_per_tx=25.0", "max_total=60.0", "confirm_above=10.0", "quarantine", "verify_memory"]
T0 = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)
CLEAN = [{"tool": "read_memory", "untrusted": False}, {"tool": "get_price", "untrusted": False}]
TAINTED = [{"tool": "read_memory", "untrusted": False}, {"tool": "browse", "untrusted": True}]


def row(guards=REC, limit=5000, agent="naive", preset="recommended"):
    return {"run": f"{agent}/{preset}", "agent": agent, "preset": preset, "guards": guards, "score": 100,
            "limit": limit, "trials": 3, "mutations": len(MUTATIONS), "utility_under_attack": 1.0}


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


@pytest.fixture
def world(tmp_path):
    net = FakeDevnet()
    ledger = SolanaLedger(net, KeyStore(tmp_path / "keys.json"), poll=0, confirm_timeout=1)
    for n in (TREASURY, AGENT):
        net.lamports[str(ledger.pubkey(n))] = 10 ** 9
    net.mint_to(ledger, TREASURY, 1000)
    ledger.fee_payer = TREASURY
    ledger.create_multisig_vault(AGENT, COSIGNER)
    ledger.fund_vault(AGENT, 100)
    ledger.fee_payer = AGENT
    for n in (DEX, ATTACKER, "forecast_api"):
        ledger.pubkey(n)                    # known names, like a real keystore after a crash test
    runs = {"naive/recommended": row()}
    clock = Clock()
    key = Ed25519PrivateKey.generate()
    cos = Cosigner(ledger, COSIGNER, key, runs.get, tmp_path / "logs" / "guard.log", clock=clock)
    return net, ledger, cos, runs, clock, key, tmp_path


def build(ledger, recipient, amount, signers=(AGENT, COSIGNER), sign=(AGENT,), payer=AGENT, extra=(),
          vault_agent=AGENT):
    ixs = ledger._transfer_ixs(ledger.multisig_name(vault_agent), recipient, amount, "", signers=list(signers))
    msg = Message.new_with_blockhash(ixs + list(extra), ledger.pubkey(payer), Hash.new_unique())
    tx = Transaction.new_unsigned(msg)
    tx.partial_sign([ledger.keys.keypair(n) for n in sign], msg.recent_blockhash)
    return base64.b64encode(bytes(tx)).decode()


def ask(cos, tx, run_id="naive/recommended", calls=CLEAN, **kw):
    return cos.decide({"tx": tx, "run_id": run_id, "tool_calls": calls, **kw})


def vault_balance(ledger):
    return ledger.balance(ledger.multisig_name(AGENT))


def log_lines(tmp_path):
    return [json.loads(l) for l in (tmp_path / "logs" / "guard.log").read_text().splitlines()]


# --- approve ---------------------------------------------------------------------------
def test_legit_transfer_is_cosigned_submitted_and_logged(world):
    net, ledger, cos, *_ , tmp = world
    r = ask(cos, build(ledger, DEX, 2))
    assert r["decision"] == "approve" and r["signature"] in net.txs
    assert vault_balance(ledger) == 98 and ledger.balance(DEX) == 2
    [line] = log_lines(tmp)
    assert line["decision"] == "approve" and line["recipient_name"] == DEX and line["amount"] == 2
    assert line["signature"] == r["signature"] and line["run_id"] == "naive/recommended"


# --- transaction checks --------------------------------------------------------------------
def test_malformed_transaction(world):
    _, _, cos, *_ = world
    for tx in ("not base64!", base64.b64encode(b"junk").decode(), None):
        assert ask(cos, tx) == {"decision": "refuse", "reason": "malformed transaction: expected a base64 "
                                                                "serialized Solana transaction"}


def test_cosigner_must_be_a_required_signer(world):
    _, ledger, cos, *_ = world
    ixs = ledger._transfer_ixs(AGENT, DEX, 1, "")                  # agent's own wallet, not the vault
    msg = Message.new_with_blockhash(ixs, ledger.pubkey(AGENT), Hash.new_unique())
    tx = Transaction([ledger.keys.keypair(AGENT)], msg, msg.recent_blockhash)
    r = ask(cos, base64.b64encode(bytes(tx)).decode())
    assert r["decision"] == "refuse" and "not a required signer" in r["reason"]


def test_cosigner_never_pays_fees_or_rent(world):
    _, ledger, cos, *_ = world
    assert "does not pay fees" in ask(cos, build(ledger, DEX, 1, payer=COSIGNER, sign=(AGENT,)))["reason"]
    ledger.fee_payer = COSIGNER                                     # ATA rent from the cosigner
    tx = build(ledger, ATTACKER, 1)
    ledger.fee_payer = AGENT
    assert "does not pay account rent" in ask(cos, tx)["reason"]


def test_agent_signature_required_and_valid(world):
    _, ledger, cos, *_ = world
    r = ask(cos, build(ledger, DEX, 1, sign=()))
    assert r["decision"] == "refuse" and f"signature from {AGENT}" in r["reason"]
    raw = bytearray(base64.b64decode(build(ledger, DEX, 1)))
    raw[-1] ^= 1                                                    # tamper with the signed message
    assert "invalid signature" in ask(cos, base64.b64encode(bytes(raw)).decode())["reason"]


def test_only_usdc_transfer_instructions(world):
    _, ledger, cos, *_ = world
    sneak = transfer(TransferParams(from_pubkey=ledger.pubkey(AGENT), to_pubkey=ledger.pubkey(ATTACKER),
                                    lamports=1))
    assert "instruction not allowed" in ask(cos, build(ledger, DEX, 1, extra=[sneak]))["reason"]
    second = ledger._transfer_ixs(ledger.multisig_name(AGENT), ATTACKER, 1, "", signers=[AGENT, COSIGNER])[1]
    assert "exactly one money move, found 2" in ask(cos, build(ledger, DEX, 1, extra=[second]))["reason"]


def test_wrong_mint(world):
    net, ledger, cos, *_ = world
    other = SolanaLedger(net, ledger.keys, mint="So11111111111111111111111111111111111111112", poll=0)
    other.fee_payer = AGENT
    assert "not a USDC transfer" in ask(cos, build(other, DEX, 1))["reason"]


def test_source_must_be_a_vault_this_cosigner_belongs_to(world):
    net, ledger, cos, *_ = world
    ledger.fee_payer = TREASURY
    ledger.create_multisig_vault("agent2", "cosigner2")
    ledger.fee_payer = AGENT
    tx = build(ledger, DEX, 1, signers=("agent2", COSIGNER), sign=(AGENT, "agent2"), vault_agent="agent2")
    assert "not a 2-of-2 vault that this cosigner belongs to" in ask(cos, tx)["reason"]


# --- attestation --------------------------------------------------------------------------
def test_attestation_sent_along_is_verified(world):
    _, ledger, cos, runs, clock, key, _ = world
    env = signed_limit(row(), key, T0)
    assert ask(cos, build(ledger, DEX, 1), attestation=env)["decision"] == "approve"

    forged = json.loads(json.dumps(env)); forged["payload"]["policy"]["per_tx_cap"] = 10 ** 6
    assert "bad signature" in ask(cos, build(ledger, DEX, 1), attestation=forged)["reason"]
    other = signed_limit(row(), Ed25519PrivateKey.generate(), T0)
    assert "untrusted key" in ask(cos, build(ledger, DEX, 1), attestation=other)["reason"]
    clock.now = T0 + timedelta(days=8)
    assert "expired" in ask(cos, build(ledger, DEX, 1), attestation=env)["reason"]


def test_attestation_must_match_the_run_and_carry_a_policy(world):
    _, ledger, cos, runs, clock, key, _ = world
    wrong = signed_limit(row(agent="openai:x"), key, T0)
    assert "not run naive/recommended" in ask(cos, build(ledger, DEX, 1), attestation=wrong)["reason"]
    bare = attest(row(), key, T0)                                   # score attestation, no policy
    assert "no spending policy" in ask(cos, build(ledger, DEX, 1), attestation=bare)["reason"]
    assert "no crash-test run 'nope'" in ask(cos, build(ledger, DEX, 1), run_id="nope")["reason"]


# --- limit, per-tx and daily caps ----------------------------------------------------------------
def test_zero_limit_refuses_everything(world):
    _, ledger, cos, runs, *_ = world
    runs["naive/recommended"] = row(limit=0)
    assert "limit is 0" in ask(cos, build(ledger, DEX, 1))["reason"]


def test_per_tx_cap(world):
    _, ledger, cos, *_ = world
    r = ask(cos, build(ledger, DEX, 26))
    assert r["decision"] == "refuse" and r["reason"] == "26 USDC is over the per-tx cap of 25"
    assert ask(cos, build(ledger, DEX, 25))["decision"] == "approve"


def test_daily_cap_counts_24h_and_survives_a_restart(world):
    _, ledger, cos, runs, clock, key, tmp = world
    runs["naive/recommended"] = row(limit=50)                       # per-tx 25, daily 50
    assert ask(cos, build(ledger, DEX, 25))["decision"] == "approve"
    clock.now = T0 + timedelta(hours=1)
    assert ask(cos, build(ledger, DEX, 20))["decision"] == "approve"
    r = ask(cos, build(ledger, DEX, 10))
    assert r["decision"] == "refuse" and "daily cap: 45 USDC cosigned" in r["reason"]

    again = Cosigner(ledger, COSIGNER, key, runs.get, tmp / "logs" / "guard.log", clock=clock)
    assert "daily cap" in ask(again, build(ledger, DEX, 10))["reason"]   # totals rebuilt from the log
    clock.now = T0 + timedelta(hours=24, minutes=1)                       # the first 25 rolled off
    assert ask(again, build(ledger, DEX, 10))["decision"] == "approve"


# --- taint + allowlist --------------------------------------------------------------------------
def test_taint_refuses_unlisted_recipients_after_untrusted_reads(world):
    _, ledger, cos, runs, *_ , tmp = world
    runs["naive/caps"] = row(["max_per_tx=25.0", "max_total=60.0"], 50, preset="caps")   # no allowlist
    assert ask(cos, build(ledger, ATTACKER, 3), "naive/caps")["decision"] == "approve"   # clean episode
    r = ask(cos, build(ledger, ATTACKER, 3), "naive/caps", TAINTED)
    assert r["decision"] == "refuse"
    assert r["reason"] == f"untrusted input was read this episode (browse) and recipient {ATTACKER} is not on the allowlist"
    assert log_lines(tmp)[-1]["untrusted_tools"] == ["browse"]
    assert ask(cos, build(ledger, DEX, 3), "naive/caps", TAINTED)["decision"] == "refuse"  # no list at all

    cos.allow = [DEX, str(ledger.pubkey("forecast_api"))]           # guard --allow (names or addresses)
    assert ask(cos, build(ledger, DEX, 3), "naive/caps", TAINTED)["decision"] == "approve"
    assert ask(cos, build(ledger, "forecast_api", 1), "naive/caps", TAINTED)["decision"] == "approve"


def test_policy_allowlist_holds_even_without_taint(world):
    _, ledger, cos, *_ = world
    r = ask(cos, build(ledger, ATTACKER, 3))
    assert r == {"decision": "refuse", "reason": f"recipient {ATTACKER} is not on the allowlist"}
    r = ask(cos, build(ledger, ATTACKER, 3), calls=TAINTED)          # taint is reported first
    assert "untrusted input was read" in r["reason"]
    assert ask(cos, build(ledger, DEX, 3), calls=TAINTED)["decision"] == "approve"
    assert vault_balance(ledger) == 97 and ledger.balance(ATTACKER) == 0


def test_unknown_names_on_the_allowlist_never_create_keys(world):
    _, ledger, cos, runs, *_ = world
    runs["naive/recommended"] = row()
    before = set(ledger.keys.names())
    cos._resolve(["DVnd7Kq2xPm4R9sWQ2Rx", "not_a_wallet_yet"])
    assert set(ledger.keys.names()) == before


# --- submission + logging -------------------------------------------------------------------------
def test_submit_failure_is_an_error_and_not_counted(world, monkeypatch):
    net, ledger, cos, runs, clock, key, tmp = world
    runs["naive/recommended"] = row(limit=25)
    monkeypatch.setattr(net, "sendTransaction", lambda *a: (_ for _ in ()).throw(RpcError("blockhash not found")))
    r = ask(cos, build(ledger, DEX, 25))
    assert r["decision"] == "error" and "blockhash not found" in r["reason"] and "signature" not in r
    monkeypatch.undo()
    assert ask(cos, build(ledger, DEX, 25))["decision"] == "approve"    # the failed one didn't use the cap


def test_every_decision_is_logged_and_keys_never_are(world):
    _, ledger, cos, *_ , tmp = world
    ask(cos, build(ledger, DEX, 1)); ask(cos, build(ledger, ATTACKER, 1)); ask(cos, "junk")
    lines = log_lines(tmp)
    assert [l["decision"] for l in lines] == ["approve", "refuse", "refuse"]
    assert all({"ts", "decision", "reason", "run_id"} <= set(l) for l in lines)
    text = (tmp / "logs" / "guard.log").read_text()
    from solders.keypair import Keypair
    for secret in json.loads(ledger.keys.path.read_text()).values():
        assert str(Keypair.from_bytes(bytes(secret))) not in text


# --- HTTP + CLI -------------------------------------------------------------------------------
def test_http_endpoint_and_runs_lookup(world):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from cosign.guard_service import create_app
    _, ledger, _, _, clock, key, tmp = world
    d = tmp / "runs" / "20261118T000000Z"
    d.mkdir(parents=True)
    old = {k: v for k, v in row().items() if k != "run"}           # rows from before the run key
    d.joinpath("results.json").write_text(json.dumps([old]))
    find = runs_lookup(tmp / "runs")
    assert find("naive/recommended")["limit"] == 5000 and find("naive--recommended") and find("x/y") is None

    cos = Cosigner(ledger, COSIGNER, key, find, tmp / "g.log", clock=clock)
    client = TestClient(create_app(cos))
    assert client.get("/v1/health").json()["cosigner"] == str(ledger.pubkey(COSIGNER))
    r = client.post("/v1/cosign", json={"tx": build(ledger, DEX, 2), "run_id": "naive/recommended",
                                        "tool_calls": TAINTED}).json()
    assert r["decision"] == "approve" and r["signature"]


def test_cli_guard_serve(world, monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    import uvicorn
    from cosign import cli
    _, ledger, *_ = world
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(tmp_path / "issuer.json"))
    monkeypatch.setattr("cosign.solana_ledger.SolanaLedger.from_env", classmethod(lambda cls: ledger))
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port: seen.update(app=app, port=port))
    assert cli.main(["guard", "serve", "--runs-dir", str(tmp_path), "--log", str(tmp_path / "g.log"),
                     "--allow", DEX]) == 0
    assert seen["port"] == 8100
