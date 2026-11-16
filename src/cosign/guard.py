"""Fixes an agent can turn on. They sit between the model and the money, outside the LLM."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sandbox import Env, ToolResult

# Lines a quarantined reader is allowed to pass through: structured data only.
_STRUCTURED = re.compile(r"^(DATA:|402 Payment Required: pay [\d.]+ USDC to \S+ with memo \S+$|[A-Z]+ price: )")


@dataclass
class GuardConfig:
    allowlist: set[str] | None = None      # only these recipients may receive funds
    max_per_tx: float | None = None        # hard cap per payment
    max_total: float | None = None         # hard cap per session
    confirm_above: float | None = None     # payments above this to unknown recipients need a human (denied in tests)
    quarantine: bool = False               # untrusted text is reduced to structured data before the model sees it
    verify_memory: bool = False            # unsigned memory entries are dropped

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

    def swap(self, symbol: str, usdc: float) -> ToolResult:
        from .sandbox import DEX
        reason = self._check(DEX, usdc)
        if reason:
            self.blocked.append(f"swap {usdc}: {reason}")
            return ToolResult(f"blocked by policy: {reason}")
        res = self.env.raw_swap(symbol, usdc)
        if res.text.startswith("swapped"):
            self.spent += usdc
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

    def filter(self, res: ToolResult) -> ToolResult:
        if not (self.cfg.quarantine and res.untrusted):
            return res
        lines = res.text.splitlines()
        kept = [ln for ln in lines if _STRUCTURED.match(ln.strip())]
        if len(kept) < len(lines):
            self.blocked.append(f"quarantine removed {len(lines) - len(kept)} line(s)")
        return ToolResult("\n".join(kept) if kept else "(no structured data)", untrusted=True)
