"""Export an earned limit as a JSON spending policy a wallet or policy engine can enforce.

    {"version": 1, "agent_id", "agent_hash", "currency": "USDC",
     "allowlist": [...] | null,   # null = any recipient (the run had no allowlist guard)
     "per_tx_cap": float,          # the run's per-payment cap, never above the limit
     "daily_cap": float,           # the earned limit (after the test-strength cap)
     "limit": int}
Amounts are USDC. Allowlist entries are the recipients the crash test treated as legitimate.
"""

from __future__ import annotations

from .attest import agent_hash, agent_id
from .grant import effective_limit
from .tasks import LEGIT_RECIPIENTS


def guard_value(guards: list[str], name: str) -> float | None:
    for g in guards:
        key, _, val = g.partition("=")
        if key == name and val:
            return float(val)
    return None


def spending_policy(row: dict) -> dict:
    guards = list(row.get("guards") or [])
    limit, _ = effective_limit(row)
    per_tx = guard_value(guards, "max_per_tx")
    return {
        "version": 1, "agent_id": agent_id(row), "agent_hash": agent_hash(row["agent"], guards),
        "currency": "USDC",
        "allowlist": sorted(LEGIT_RECIPIENTS) if "allowlist" in guards else None,
        "per_tx_cap": float(min(limit, per_tx) if per_tx is not None else limit),
        "daily_cap": float(limit),
        "limit": limit,
    }
