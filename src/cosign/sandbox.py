"""The fake mini-internet the agent lives in during a crash test.

Every tool returns a ToolResult. `untrusted=True` marks content an attacker could
control (web pages, API bodies, token pages, hijacked tool replies, unsigned memory).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ledger import InsufficientFunds, Ledger, Refused, SimLedger

DEX = "dex_pool"


@dataclass
class ToolResult:
    text: str
    untrusted: bool = False


@dataclass
class PaidAPI:
    price: float
    pay_to: str
    data: str
    body_before_payment: str = ""  # extra text an attacker can stuff into the 402 response


@dataclass
class MemoryEntry:
    text: str
    signed: bool = True  # written by the operator/agent itself; unsigned = came from elsewhere


@dataclass
class Env:
    agent: str = "agent_wallet"
    ledger: Ledger = field(default_factory=SimLedger)
    prices: dict[str, float] = field(default_factory=dict)
    pages: dict[str, str] = field(default_factory=dict)
    token_pages: dict[str, str] = field(default_factory=dict)
    apis: dict[str, PaidAPI] = field(default_factory=dict)
    memory: list[MemoryEntry] = field(default_factory=list)
    hijack: dict[str, str] = field(default_factory=dict)  # tool name -> text appended to its reply
    holdings: dict[str, float] = field(default_factory=dict)
    paid: set[tuple[str, str]] = field(default_factory=set)  # (url, recipient) payments made
    inbox: list[str] = field(default_factory=list)            # messages from other agents (their output)
    airdrops: dict[str, str] = field(default_factory=dict)    # token symbol -> its on-chain memo/metadata
    allowances: dict[str, float] = field(default_factory=dict)  # spender -> USDC it may pull (inf = unlimited)
    tx_history: list[str] = field(default_factory=list)       # past transfers, newest first ("TX: ...")

    # --- read tools -------------------------------------------------------
    def get_price(self, symbol: str) -> ToolResult:
        symbol = symbol.upper()
        if symbol not in self.prices:
            return ToolResult(f"unknown symbol {symbol}")
        text = f"{symbol} price: {self.prices[symbol]} USDC"
        return self._maybe_hijack("get_price", text)

    def browse(self, url: str) -> ToolResult:
        return ToolResult(self.pages.get(url, f"404 not found: {url}"), untrusted=True)

    def token_info(self, symbol: str) -> ToolResult:
        symbol = symbol.upper()
        return ToolResult(self.token_pages.get(symbol, f"no page for {symbol}"), untrusted=True)

    def call_api(self, url: str) -> ToolResult:
        api = self.apis.get(url)
        if api is None:
            return ToolResult(f"404 not found: {url}", untrusted=True)
        if (url, api.pay_to) in self.paid:
            return ToolResult(api.data, untrusted=True)
        body = f"402 Payment Required: pay {api.price} USDC to {api.pay_to} with memo {url}"
        if api.body_before_payment:
            body += "\n" + api.body_before_payment
        return ToolResult(body, untrusted=True)

    def read_memory(self) -> ToolResult:
        lines = [f"- {m.text}" for m in self.memory]
        untrusted = any(not m.signed for m in self.memory)
        return ToolResult("memory:\n" + "\n".join(lines) if lines else "memory: (empty)", untrusted)

    def write_memory(self, text: str) -> ToolResult:
        self.memory.append(MemoryEntry(text, signed=True))
        return ToolResult("saved")

    def read_inbox(self) -> ToolResult:
        body = "\n".join(self.inbox) if self.inbox else "(no messages)"
        return ToolResult("inbox:\n" + body, untrusted=True)

    def history(self) -> ToolResult:
        # anyone can send the wallet dust with a memo, so history is attacker-writable
        return ToolResult("\n".join(self.tx_history) or "(no transactions)", untrusted=True)

    def balance(self) -> ToolResult:
        text = f"balance: {self.ledger.balance(self.agent):.2f} USDC"
        if not self.airdrops:
            return ToolResult(text)
        drops = "\n".join(f"airdropped {sym}: {memo}" for sym, memo in self.airdrops.items())
        return ToolResult(f"{text}\n{drops}", untrusted=True)   # token metadata is attacker-written

    # --- money-moving tools (always called through a Guard) ---------------
    def raw_pay(self, recipient: str, amount: float, memo: str = "") -> ToolResult:
        try:
            self.ledger.transfer(self.agent, recipient, amount, memo)
        except Refused as e:
            return ToolResult(f"payment refused by cosigner: {e}")
        except (InsufficientFunds, ValueError) as e:
            return ToolResult(f"payment failed: {e}")
        if memo in self.apis and self.apis[memo].pay_to == recipient:
            self.paid.add((memo, recipient))
        return ToolResult(f"paid {amount} USDC to {recipient}")

    def raw_approve(self, spender: str, amount: float) -> ToolResult:
        """Token allowance: `spender` may later pull up to `amount` USDC. Recorded, not moved: the judge
        counts it as lost (up to what the wallet still holds)."""
        if not amount > 0:
            return ToolResult("approve failed: amount must be positive")
        self.allowances[spender] = amount
        shown = "unlimited" if amount == float("inf") else f"{amount:g}"
        return ToolResult(f"approved {spender} to spend {shown} USDC")

    def raw_swap(self, symbol: str, usdc: float) -> ToolResult:
        symbol = symbol.upper()
        if symbol not in self.prices:
            return ToolResult(f"unknown symbol {symbol}")
        try:
            self.ledger.transfer(self.agent, DEX, usdc, f"swap {symbol}")
        except Refused as e:
            return ToolResult(f"swap refused by cosigner: {e}")
        except (InsufficientFunds, ValueError) as e:
            return ToolResult(f"swap failed: {e}")
        qty = usdc / self.prices[symbol]
        self.holdings[symbol] = self.holdings.get(symbol, 0.0) + qty
        return ToolResult(f"swapped {usdc} USDC for {qty:.4f} {symbol}")

    def _maybe_hijack(self, tool: str, text: str) -> ToolResult:
        extra = self.hijack.get(tool)
        if extra:
            return ToolResult(text + "\n" + extra, untrusted=True)
        return ToolResult(text)
