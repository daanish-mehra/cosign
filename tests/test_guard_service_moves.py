"""cosign guard on every money move out of the vault: approvals, authority changes, recurring payments,
bridges and swaps. Each is refused unless its counterparty is allowlisted, under the same taint rule as
transfers, and checked against the caps for the money it puts at risk. Fake devnet, no network."""

import base64

import pytest

pytest.importorskip("solders")
pytest.importorskip("spl")

from solders.hash import Hash  # noqa: E402
from solders.message import Message  # noqa: E402
from solders.pubkey import Pubkey  # noqa: E402
from solders.transaction import Transaction  # noqa: E402
from spl.token.constants import TOKEN_PROGRAM_ID  # noqa: E402
from spl.token.instructions import AuthorityType, approve, approve_checked, set_authority  # noqa: E402
from spl.token.models import ApproveCheckedParams, ApproveParams, SetAuthorityParams  # noqa: E402
from test_guard_service import AGENT, CLEAN, COSIGNER, DEX, TAINTED, ask, log_lines, world  # noqa: E402,F401

from cosign.attacks import ATTACKER  # noqa: E402
from cosign.guard_service import BRIDGE, U64_MAX  # noqa: E402

PAYEE = "forecast_api"          # on the policy allowlist, like DEX


def sign(ledger, ixs):
    msg = Message.new_with_blockhash(ixs, ledger.pubkey(AGENT), Hash.new_unique())
    tx = Transaction.new_unsigned(msg)
    tx.partial_sign([ledger.keys.keypair(AGENT)], msg.recent_blockhash)
    return base64.b64encode(bytes(tx)).decode()


def members(ledger):
    return [ledger.pubkey(AGENT), ledger.pubkey(COSIGNER)]


def vault(ledger):
    v = ledger.multisig_vault(AGENT)
    return Pubkey.from_string(v["token_account"]), Pubkey.from_string(v["multisig"])


def transfer_tx(ledger, to, amount, memo):
    return sign(ledger, ledger._transfer_ixs(ledger.multisig_name(AGENT), to, amount, memo, signers=[AGENT, COSIGNER]))


def approve_tx(ledger, spender, amount, checked=True):
    src, ms = vault(ledger)
    units = U64_MAX if amount == "unlimited" else int(amount * 10 ** 6)
    if checked:
        ix = approve_checked(ApproveCheckedParams(program_id=TOKEN_PROGRAM_ID, source=src,
                                                  mint=Pubkey.from_string(ledger.mint), delegate=ledger.pubkey(spender),
                                                  owner=ms, amount=units, decimals=6, signers=members(ledger)))
    else:
        ix = approve(ApproveParams(program_id=TOKEN_PROGRAM_ID, source=src, delegate=ledger.pubkey(spender),
                                   owner=ms, amount=units, signers=members(ledger)))
    return sign(ledger, [ix])


def authority_tx(ledger, new, kind=AuthorityType.ACCOUNT_OWNER):
    src, ms = vault(ledger)
    return sign(ledger, [set_authority(SetAuthorityParams(
        program_id=TOKEN_PROGRAM_ID, account=src, authority=kind, current_authority=ms,
        new_authority=ledger.pubkey(new) if new else None, signers=members(ledger)))])


def set_vault_balance(net, ledger, usdc):
    net.tokens[str(vault(ledger)[0])] = int(usdc * 10 ** 6)


@pytest.fixture
def moves(world):
    net, ledger, cos, *_ = world
    ledger.pubkey(BRIDGE)               # the bridge escrow is a known name, like dex_pool
    return world


# build(ledger, counterparty) for each move, small enough to sit under the caps
MOVES = {
    "approve": lambda l, who: approve_tx(l, who, 5),
    "approve_unchecked": lambda l, who: approve_tx(l, who, 5, checked=False),
    "authority": lambda l, who: authority_tx(l, who),
    "recurring": lambda l, who: transfer_tx(l, who, 1, "recurring every_days=30"),
    "bridge": lambda l, who: transfer_tx(l, BRIDGE, 2, f"ethereum:{l.pubkey(who)}"),
    "swap": lambda l, who: transfer_tx(l, who, 2, "swap SOL slippage_bps=50"),
}
ROLE = {"approve": "spender", "approve_unchecked": "spender", "authority": "new authority",
        "recurring": "recipient", "bridge": "bridge destination", "swap": "recipient"}


@pytest.mark.parametrize("move", sorted(MOVES))
def test_unlisted_counterparty_is_refused(moves, move):
    net, ledger, cos, *_ = moves
    set_vault_balance(net, ledger, 20)
    r = ask(cos, MOVES[move](ledger, ATTACKER))
    assert r == {"decision": "refuse", "reason": f"{ROLE[move]} {ATTACKER} is not on the allowlist"}
    assert net.sent == 0 or "signature" not in r


@pytest.mark.parametrize("move", sorted(MOVES))
def test_taint_rule_names_the_untrusted_reads(moves, move):
    net, ledger, cos, *_ = moves
    set_vault_balance(net, ledger, 20)
    r = ask(cos, MOVES[move](ledger, ATTACKER), calls=TAINTED)
    assert r["decision"] == "refuse"
    assert r["reason"] == f"untrusted input was read this episode (browse) and {ROLE[move]} {ATTACKER} is not on the allowlist"


@pytest.mark.parametrize("move", sorted(MOVES))
def test_allowlisted_counterparty_is_cosigned_even_when_tainted(moves, move):
    net, ledger, cos, *_, tmp = moves
    set_vault_balance(net, ledger, 20)
    sent = net.sent
    r = ask(cos, MOVES[move](ledger, PAYEE), calls=TAINTED)
    assert r["decision"] == "approve", r
    assert net.sent == sent + 1
    kind = "approve" if move.startswith("approve") else move
    assert log_lines(tmp)[-1]["kind"] == kind and log_lines(tmp)[-1]["recipient_name"] == PAYEE


def test_approval_lands_as_a_delegate_and_unlimited_is_over_every_cap(moves):
    net, ledger, cos, *_ = moves
    assert ask(cos, approve_tx(ledger, PAYEE, 5))["decision"] == "approve"
    assert net.delegate[str(vault(ledger)[0])] == (str(ledger.pubkey(PAYEE)), 5 * 10 ** 6)
    r = ask(cos, approve_tx(ledger, PAYEE, "unlimited"))
    assert r["reason"] == "unlimited USDC at risk (approve) is over the per-tx cap of 25"
    assert ask(cos, approve_tx(ledger, PAYEE, 26))["reason"].startswith("26 USDC at risk (approve)")


def test_authority_change_risks_the_whole_balance(moves):
    net, ledger, cos, *_ = moves
    r = ask(cos, authority_tx(ledger, PAYEE))                         # the vault holds 100
    assert r["reason"] == "100 USDC at risk (authority) is over the per-tx cap of 25"
    assert ask(cos, authority_tx(ledger, None))["reason"] == "removing the vault's authority is not allowed"
    set_vault_balance(net, ledger, 20)
    assert ask(cos, authority_tx(ledger, PAYEE))["decision"] == "approve"
    assert net.owner[str(vault(ledger)[0])] == str(ledger.pubkey(PAYEE))


def test_recurring_payment_is_judged_by_its_total(moves):
    _, ledger, cos, *_ = moves
    r = ask(cos, transfer_tx(ledger, DEX, 1, "recurring every_days=1"))   # 30 payments in 30 days
    assert r["reason"] == "30 USDC at risk (recurring) is over the per-tx cap of 25"
    r = ask(cos, transfer_tx(ledger, DEX, 5, "recurring every_days=7"))   # 5 x 5 = 25: at the cap
    assert r["decision"] == "approve" and r["reason"] == "recurring: 25 USDC to dex_pool within policy"


def test_bridge_is_checked_against_its_destination_not_the_escrow(moves):
    _, ledger, cos, *_ = moves
    r = ask(cos, transfer_tx(ledger, BRIDGE, 2, f"solana:{PAYEE}"))           # by name works too
    assert r["decision"] == "approve" and r["reason"] == "bridge: 2 USDC to forecast_api within policy"
    r = ask(cos, transfer_tx(ledger, BRIDGE, 2, ""))
    assert r["reason"] == 'bridge transfer without a destination: memo must be "<chain>:<address>"'
    r = ask(cos, transfer_tx(ledger, BRIDGE, 2, "ethereum:0xdeadbeef"))     # unknown: never trusted
    assert r["reason"] == "bridge destination 0xdeadbeef is not on the allowlist"


def test_swap_slippage_cap(moves):
    net, ledger, cos, *_, tmp = moves
    r = ask(cos, transfer_tx(ledger, DEX, 20, "swap SOL slippage_bps=5000"))
    assert r == {"decision": "refuse", "reason": "swap slippage 5000 bps is over the cap of 100 bps"}
    assert log_lines(tmp)[-1]["slippage_bps"] == 5000
    assert ask(cos, transfer_tx(ledger, DEX, 2, "swap SOL slippage_bps=100"))["decision"] == "approve"
    assert ask(cos, transfer_tx(ledger, DEX, 2, "swap BONK"))["decision"] == "approve"   # nothing declared


def test_cli_slippage_flag(moves, monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    import uvicorn
    from cosign import cli, guard_service
    _, ledger, *_ = moves
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(tmp_path / "issuer.json"))
    monkeypatch.setattr("cosign.solana_ledger.SolanaLedger.from_env", classmethod(lambda cls: ledger))
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port: None)
    made = []
    real = guard_service.Cosigner
    monkeypatch.setattr(guard_service, "Cosigner", lambda *a, **kw: made.append(real(*a, **kw)) or made[-1])
    cli.main(["guard", "serve", "--runs-dir", str(tmp_path), "--log", str(tmp_path / "g.log")])
    cli.main(["guard", "serve", "--runs-dir", str(tmp_path), "--log", str(tmp_path / "g.log"),
              "--max-slippage-bps", "30"])
    assert [c.max_slippage_bps for c in made] == [100, 30]
