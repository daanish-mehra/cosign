from cosign.adapters_solana_agent_kit import MINTS, TOOL_NAMES, SolanaAgentKitTools, symbol_of
from cosign.attacks import ATTACKER
from cosign.cli import guard_preset
from cosign.guard import Guard
from cosign.ledger import SimLedger
from cosign.sandbox import DEX
from cosign.tasks import FORECAST_PAYEE, START_BALANCE, make_world


def kit(guards="none"):
    env = make_world()
    return SolanaAgentKitTools(env, Guard(env, guard_preset(guards))), env


def test_transfer_settles_on_the_sim_ledger():
    k, env = kit()
    assert isinstance(env.ledger, SimLedger)
    assert k.transfer(FORECAST_PAYEE, 5).text == f"paid 5.0 USDC to {FORECAST_PAYEE}"
    assert k.transfer(FORECAST_PAYEE, 1, mint=MINTS["USDC"]).text.startswith("paid")
    [t1, t2] = env.ledger.transfers
    assert (t1.sender, t1.recipient, t1.amount) == (env.agent, FORECAST_PAYEE, 5.0)
    assert k.getBalance().text == f"{START_BALANCE - 6:.2f}"
    assert k.transfer(FORECAST_PAYEE, 1000).text.startswith("payment failed")


def test_swap_spends_usdc_and_fills_holdings():
    k, env = kit()
    assert k.swap(MINTS["SOL"], 15).text == "swapped 15.0 USDC for 0.1000 SOL"
    assert k.trade("BONK", 1).text.startswith("swapped")
    assert env.ledger.transfers[0].recipient == DEX
    assert k.getBalance(MINTS["SOL"]).text == "0.1" and k.getBalance("bonk").text == "50000"
    assert k.getBalance(MINTS["USDC"]).text == f"{START_BALANCE - 16:.2f}"


def test_guards_check_every_transfer_and_swap():
    k, env = kit("recommended")
    assert k.transfer(ATTACKER, 50).text == "blocked by policy: recipient not on allowlist"
    assert k.transfer(FORECAST_PAYEE, 30).text.startswith("blocked by policy: over per-tx cap")
    assert k.swap(MINTS["SOL"], 40).text.startswith("blocked by policy")
    assert k.swap(MINTS["SOL"], 20).text.startswith("swapped")
    assert [t.recipient for t in env.ledger.transfers] == [DEX]
    assert len(k.guard.blocked) == 3


def test_sandbox_limits_on_mints():
    k, env = kit()
    assert "only sends USDC" in k.transfer(ATTACKER, 1, mint=MINTS["SOL"]).text
    assert "only spends USDC" in k.swap(MINTS["USDC"], 1, inputMint=MINTS["SOL"]).text
    assert "both USDC" in k.swap("USDC", 1).text
    assert k.swap("NOPE", 1).text == "unknown symbol NOPE"
    assert env.ledger.transfers == []
    assert symbol_of(None) == "USDC" and symbol_of(MINTS["BONK"]) == "BONK" and symbol_of("sol") == "SOL"


def test_call_dispatch_by_tool_name():
    k, env = kit()
    assert TOOL_NAMES == ["transfer", "swap", "getBalance"]
    assert k.call("transfer", {"to": FORECAST_PAYEE, "amount": "2"}).text.startswith("paid 2.0")
    assert k.call("swap", {"outputMint": MINTS["SOL"], "inputAmount": 15, "slippageBps": 50}).text.startswith("swapped")
    assert k.call("get_balance", {}).text == f"{START_BALANCE - 17:.2f}"
    assert k.call("transfer", {"to": FORECAST_PAYEE}).text.startswith("bad arguments for transfer")
    assert k.call("transfer", {"to": FORECAST_PAYEE, "amount": "lots"}).text.startswith("bad arguments")
    assert k.call("stake", {}).text == "unknown tool stake"
