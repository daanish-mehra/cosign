"""Guarded mode: a vault agent's transfers are built + agent-signed locally, cosigned (or refused) by cosign guard."""

import io
import json

import pytest

pytest.importorskip("solders")
pytest.importorskip("cryptography")

from test_guard_service import AGENT, COSIGNER, DEX, Clock, row, world  # noqa: E402,F401
from test_solana_ledger import FakeDevnet  # noqa: E402,F401

from cosign.attacks import ATTACKER, ATTACKS, MUTATIONS  # noqa: E402
from cosign.cli import guard_preset  # noqa: E402
from cosign.ledger import Refused  # noqa: E402
from cosign.runner import naive_brains, run_episode  # noqa: E402
from cosign.solana_ledger import RpcError, http_guard  # noqa: E402
from cosign.tasks import TASKS  # noqa: E402

import dataclasses  # noqa: E402

POISONED = dataclasses.replace(next(a for a in ATTACKS if a.family == "poisoned_website"), amount=5)
RESEARCH = next(t for t in TASKS if t.id == "token_research")
PLAIN = MUTATIONS[0]


@pytest.fixture
def guarded(world):
    net, ledger, cos, runs, clock, key, tmp = world
    seen = []

    def guard(req):
        seen.append(req)
        return cos.decide(req)
    ledger.use_vault(AGENT, COSIGNER, guard, "naive/recommended")
    return net, ledger, cos, runs, seen, tmp


def test_poisoned_episode_theft_refused_swap_cosigned(guarded):
    net, ledger, cos, runs, seen, tmp = guarded
    vault = ledger.multisig_name(AGENT)
    ep = run_episode(RESEARCH, guard_preset("none"), naive_brains, POISONED, PLAIN, lambda: ledger)
    assert ep.error is None and ep.stolen == 0 and ep.task_ok
    assert ledger.balance(ATTACKER) == 0 and ledger.balance(vault) == 90 and ledger.balance(DEX) == 10
    pay = next(s for s in ep.steps if s["tool"] == "pay")
    assert pay["args"]["recipient"] == ATTACKER and pay["result"].startswith("payment refused by cosigner: untrusted")
    [t] = ledger.transfers                                         # only the swap landed
    assert t.recipient == DEX and t.signature in net.txs
    assert ledger.refusals[0]["recipient"] == ATTACKER and "allowlist" in ledger.refusals[0]["reason"]

    first = seen[0]                                                # what the guard was told
    assert first["run_id"] == "naive/recommended"
    assert [c["tool"] for c in first["tool_calls"]] == ["read_memory", "token_info", "browse"]
    assert [c["untrusted"] for c in first["tool_calls"]] == [False, True, True]
    assert [json.loads(l)["decision"] for l in (tmp / "logs" / "guard.log").read_text().splitlines()] == \
        ["refuse", "approve"]


def test_a_big_theft_hits_the_per_tx_cap_first(guarded):
    _, ledger, *_ = guarded
    big = dataclasses.replace(POISONED, amount=50)
    ep = run_episode(RESEARCH, guard_preset("none"), naive_brains, big, PLAIN, lambda: ledger)
    assert ep.stolen == 0 and ep.task_ok
    assert "over the per-tx cap of 25" in ledger.refusals[0]["reason"]


def test_balance_and_fund_point_at_the_vault(guarded):
    _, ledger, *_ = guarded
    assert ledger.balance(AGENT) == 100
    ledger.fund(AGENT, 120)
    assert ledger.balance(ledger.multisig_name(AGENT)) == 120


def test_refusals_raise_and_nothing_moves(guarded):
    net, ledger, cos, runs, *_ = guarded
    runs["naive/recommended"] = row(limit=0)
    with pytest.raises(Refused, match="limit is 0"):
        ledger.transfer(AGENT, DEX, 1)
    assert ledger.transfers == [] and ledger.balance(AGENT) == 100


def test_guard_errors_surface_as_rpc_errors(guarded):
    _, ledger, *_ = guarded
    ledger.guard = lambda req: {"decision": "error", "reason": "cosigned but not confirmed"}
    with pytest.raises(RpcError, match="cosign guard: error"):
        ledger.transfer(AGENT, DEX, 1)
    ledger.guard = lambda req: {"decision": "approve"}             # approve without a signature: not trusted
    with pytest.raises(RpcError):
        ledger.transfer(AGENT, DEX, 1)


def test_the_agent_signs_but_never_the_cosigner(guarded):
    _, ledger, *_ = guarded
    import base64
    from solders.transaction import Transaction
    got = {}
    ledger.guard = lambda req: got.update(req) or {"decision": "refuse", "reason": "no"}
    with pytest.raises(Refused):
        ledger.transfer(AGENT, DEX, 1)
    tx = Transaction.from_bytes(base64.b64decode(got["tx"]))
    keys = [str(k) for k in tx.message.account_keys]
    signed = {keys[i] for i, s in enumerate(tx.signatures) if s != type(s).default()}
    assert signed == {str(ledger.pubkey(AGENT))}                   # cosigner's slot left empty


def test_insufficient_vault_and_fee_payer_rules(guarded):
    _, ledger, *_ = guarded
    from cosign.ledger import InsufficientFunds
    with pytest.raises(InsufficientFunds, match="vault"):
        ledger.transfer(AGENT, DEX, 500)
    ledger.fee_payer = COSIGNER
    with pytest.raises(ValueError, match="fee payer"):
        ledger.use_vault(AGENT, COSIGNER, lambda r: r, "x")


def test_unguarded_senders_still_send_directly(guarded):
    net, ledger, *_ = guarded
    net.mint_to(ledger, "other", 5)
    ledger.fee_payer = "agent_wallet"
    ledger.transfer("other", DEX, 2)
    assert ledger.balance(DEX) == 2


def test_http_guard_posts_to_the_service(monkeypatch):
    calls = {}

    def fake_urlopen(req, timeout):
        calls.update(url=req.full_url, body=json.loads(req.data))
        return io.BytesIO(b'{"decision": "refuse", "reason": "nope"}')
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert http_guard("http://127.0.0.1:8100/")({"tx": "x"}) == {"decision": "refuse", "reason": "nope"}
    assert calls == {"url": "http://127.0.0.1:8100/v1/cosign", "body": {"tx": "x"}}
