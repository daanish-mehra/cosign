"""Fixes an agent can turn on. They sit between the model and the money, outside the LLM."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sandbox import Env, ToolResult

# Lines a quarantined reader is allowed to pass through: structured data only.
_STRUCTURED = re.compile(r"^(DATA:|TX:|balance: [\d.]+ USDC$|"
                         r"402 Payment Required: pay [\d.]+ USDC to \S+ with memo \S+$|[A-Z]+ price: )")


@dataclass
class GuardConfig:
    allowlist: set[str] | None = None      # only these recipients may receive funds
    max_per_tx: float | None = None        # hard cap per payment
    max_total: float | None = None         # hard cap per session
    confirm_above: float | None = None     # payments above this to unknown recipients need a human (denied in tests)
    quarantine: bool = False               # untrusted text is reduced to structured data before the model sees it
    verify_memory: bool = False            # unsigned memory entries are dropped
    max_slippage_bps: float | None = None  # swaps with a looser slippage tolerance are refused

    @classmethod
    def none(cls) -> "GuardConfig":
        return cls()

    @classmethod
    def recommended(cls, allowlist: set[str]) -> "GuardConfig":
        return cls(allowlist=allowlist, max_per_tx=25, max_total=60, confirm_above=10,
                   quarantine=True, verify_memory=True)

    def enabled(self) -> list[str]:
        on = []
        if self.allowlist is not None: on.append("allowlist")
        if self.max_per_tx is not None: on.append(f"max_per_tx={self.max_per_tx}")
        if self.max_total is not None: on.append(f"max_total={self.max_total}")
        if self.confirm_above is not None: on.append(f"confirm_above={self.confirm_above}")
        if self.quarantine: on.append("quarantine")
        if self.verify_memory: on.append("verify_memory")
        if self.max_slippage_bps is not None: on.append(f"max_slippage_bps={self.max_slippage_bps:g}")
        return on or ["none"]


@dataclass
class Guard:
    env: Env
    cfg: GuardConfig
    spent: float = 0.0
    blocked: list[str] = field(default_factory=list)

    # --- money ------------------------------------------------------------
    def pay(self, recipient: str, amount: float, memo: str = "") -> ToolResult:
        reason = self._check(recipient, amount)
        if reason:
            self.blocked.append(f"pay {amount} to {recipient}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_pay(recipient, amount, memo)
        if res.text.startswith("paid"):
            self.spent += amount
        return res

    def swap(self, symbol: str, usdc: float, slippage_bps: float = 50) -> ToolResult:
        """Checked as a payment to the token's pool (a scam token's pool is its deployer)."""
        reason = self._check(self.env.pool_of(symbol), usdc)
        if not reason and self.cfg.max_slippage_bps is not None and slippage_bps > self.cfg.max_slippage_bps:
            reason = f"slippage {slippage_bps:g} bps over cap {self.cfg.max_slippage_bps:g}"
        if reason:
            self.blocked.append(f"swap {usdc}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_swap(symbol, usdc, slippage_bps)
        if res.text.startswith("swapped"):
            self.spent += usdc
        return res

    def approve(self, spender: str, amount: float) -> ToolResult:
        """An allowance is money at risk: same checks as a payment of that size."""
        shown = "unlimited" if amount == float("inf") else f"{amount:g}"
        reason = self._check(spender, amount)
        if reason:
            self.blocked.append(f"approve {shown} to {spender}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_approve(spender, amount)
        if res.text.startswith("approved"):
            self.spent += amount
        return res

    def set_authority(self, new_authority: str) -> ToolResult:
        """Handing over the token account = paying out the whole balance."""
        at_risk = self.env.ledger.balance(self.env.agent)
        reason = self._check(new_authority, at_risk)
        if reason:
            self.blocked.append(f"set_authority to {new_authority}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_set_authority(new_authority)
        self.spent += at_risk
        return res

    def schedule(self, recipient: str, amount: float, every_days: float = 30) -> ToolResult:
        """A recurring payment is checked as its full total over the horizon, not one instalment."""
        from .sandbox import recurring_total
        total = recurring_total(amount, every_days) if amount > 0 and every_days > 0 else amount
        reason = self._check(recipient, total)
        if reason:
            self.blocked.append(f"schedule {amount:g} every {every_days:g}d to {recipient}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_schedule(recipient, amount, every_days)
        if res.text.startswith("scheduled"):
            self.spent += total
        return res

    def bridge(self, recipient: str, amount: float, chain: str = "ethereum") -> ToolResult:
        """Checked against the destination address, not the bridge contract."""
        reason = self._check(recipient, amount)
        if reason:
            self.blocked.append(f"bridge {amount:g} to {recipient}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_bridge(recipient, amount, chain)
        if res.text.startswith("bridged"):
            self.spent += amount
        return res

    def _check(self, recipient: str, amount: float) -> str | None:
        c = self.cfg
        known = c.allowlist is None or recipient in c.allowlist
        if c.allowlist is not None and not known:
            return "recipient not on allowlist"
        if c.max_per_tx is not None and amount > c.max_per_tx:
            return f"over per-tx cap {c.max_per_tx}"
        if c.max_total is not None and self.spent + amount > c.max_total:
            return f"over session cap {c.max_total}"
        if c.confirm_above is not None and amount > c.confirm_above and (c.allowlist is None or not known):
            return "needs human confirmation (denied)"
        return None

    # --- what the model is allowed to read --------------------------------
    def read_memory(self) -> ToolResult:
        if not self.cfg.verify_memory:
            return self.env.read_memory()
        kept = [m for m in self.env.memory if m.signed]
        dropped = len(self.env.memory) - len(kept)
        if dropped:
            self.blocked.append(f"dropped {dropped} unsigned memory entr{'y' if dropped == 1 else 'ies'}")
        lines = [f"- {m.text}" for m in kept]
        return ToolResult("memory:\n" + "\n".join(lines) if lines else "memory: (empty)")

    def tool_notes(self) -> dict[str, str]:
        """Third-party tool-description text the brain may see. Quarantine treats it like any untrusted text."""
        if not self.cfg.quarantine:
            return dict(self.env.tool_notes)
        kept = {}
        for tool, text in self.env.tool_notes.items():
            res = self.filter(ToolResult(text, untrusted=True))
            if res.text != "(no structured data)":
                kept[tool] = res.text
        return kept

    def filter(self, res: ToolResult) -> ToolResult:
        if not (self.cfg.quarantine and res.untrusted):
            return res
        lines = res.text.splitlines()
        kept = [ln for ln in lines if _STRUCTURED.match(ln.strip())]
        if len(kept) < len(lines):
            self.blocked.append(f"quarantine removed {len(lines) - len(kept)} line(s)")
        return ToolResult("\n".join(kept) if kept else "(no structured data)", untrusted=True)
