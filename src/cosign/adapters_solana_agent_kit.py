"""Solana Agent Kit-style tools (transfer, swap, getBalance) on cosign's ledger.

For agents written against the kit's interface (sendaifun's solana-agent-kit): the same method
and argument names, but every transfer and swap goes through a cosign Guard and settles on the
Env's ledger (SimLedger by default) instead of mainnet. So a kit-style agent can be crash-tested
in-process, and the judge sees exactly what moved.

    kit = SolanaAgentKitTools(env, guard)
    kit.transfer(to="dex_pool", amount=5)                 # -> Guard.pay
    kit.swap(outputMint=MINTS["SOL"], inputAmount=20)     # -> Guard.swap (USDC in)
    kit.getBalance(MINTS["USDC"])
    kit.call("transfer", {"to": ..., "amount": ...})      # dispatch by tool name, for tool-calling agents

Differences from the real kit, because the sim wallet is USDC-only:
- transfer and getBalance default to USDC when no mint is given (the real kit defaults to native SOL).
- transfer only sends USDC; swap only spends USDC. Other mints are refused with a clear message.
- Results are text (ToolResult), not transaction signatures.
Tokens can be named by mint address or by symbol.
"""

from __future__ import annotations

from typing import Any

from .guard import Guard
from .sandbox import Env, ToolResult

MINTS = {
    "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "SOL": "So11111111111111111111111111111111111111112",
    "BONK": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
}
SYMBOLS = {mint: sym for sym, mint in MINTS.items()}


def symbol_of(token: str | None, default: str = "USDC") -> str:
    """Mint address or symbol -> symbol. Unknown mints are returned as given (upper-cased)."""
    if token is None or token == "":
        return default
    return SYMBOLS.get(token, str(token).upper())


def _num(schema_type: str = "number") -> dict[str, str]:
    return {"type": schema_type}


TOOL_SPECS: list[dict[str, Any]] = [
    {"name": "transfer", "description": "Transfer tokens to a wallet. mint defaults to USDC in this sandbox.",
     "parameters": {"type": "object", "properties": {"to": _num("string"), "amount": _num(), "mint": _num("string")},
                    "required": ["to", "amount"]}},
    {"name": "swap", "description": "Swap tokens via the DEX. Spends inputAmount of inputMint (USDC).",
     "parameters": {"type": "object", "properties": {"outputMint": _num("string"), "inputAmount": _num(),
                                                     "inputMint": _num("string"), "slippageBps": _num("integer")},
                    "required": ["outputMint", "inputAmount"]}},
    {"name": "getBalance", "description": "Wallet balance of a token (default USDC).",
     "parameters": {"type": "object", "properties": {"token_address": _num("string")}, "required": []}},
]
TOOL_NAMES = [t["name"] for t in TOOL_SPECS]
ALIASES = {"trade": "swap", "get_balance": "getBalance", "balance": "getBalance"}


class SolanaAgentKitTools:
    def __init__(self, env: Env, guard: Guard):
        self.env, self.guard = env, guard

    def transfer(self, to: str, amount: float, mint: str | None = None) -> ToolResult:
        sym = symbol_of(mint)
        if sym != "USDC":
            return ToolResult(f"transfer failed: the sandbox wallet only sends USDC, not {sym}")
        return self.guard.pay(str(to), float(amount), "transfer")

    def swap(self, outputMint: str, inputAmount: float, inputMint: str | None = None,
             slippageBps: int | None = None) -> ToolResult:
        sym_in, sym_out = symbol_of(inputMint), symbol_of(outputMint)
        if sym_in != "USDC":
            return ToolResult(f"swap failed: the sandbox wallet only spends USDC, not {sym_in}")
        if sym_out == "USDC":
            return ToolResult("swap failed: input and output are both USDC")
        return self.guard.swap(sym_out, float(inputAmount))

    trade = swap  # the kit's older name for the same action

    def getBalance(self, token_address: str | None = None) -> ToolResult:
        sym = symbol_of(token_address)
        if sym == "USDC":
            return ToolResult(f"{self.env.ledger.balance(self.env.agent):.2f}")
        return ToolResult(f"{self.env.holdings.get(sym, 0.0):g}")

    def call(self, name: str, args: dict[str, Any] | None = None) -> ToolResult:
        """Run a tool by name (kit names, plus trade/get_balance aliases)."""
        name = ALIASES.get(name, name)
        if name not in TOOL_NAMES:
            return ToolResult(f"unknown tool {name}")
        try:
            return getattr(self, name)(**(args or {}))
        except (TypeError, ValueError) as e:
            return ToolResult(f"bad arguments for {name}: {e}")
