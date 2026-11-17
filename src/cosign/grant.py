"""Turn a crash-test rating into an on-chain allowance (SPL token delegation).

The operator's USDC vault approves the agent's key as delegate for exactly the earned limit,
scaled to real USDC, or revokes the delegate when the limit is 0. The token program then
enforces the limit: the agent can't move more, no matter what its model or software decides.
"""

from __future__ import annotations

from .scoring import LIMIT_TIERS, cap_by_test_strength

DEMO_MAX_USDC = 20.0   # devnet demo: the top tier (5000) maps to 20 USDC


def effective_limit(row: dict) -> tuple[int, list[str]]:
    """The row's limit, re-checked against the test-strength cap. Rows that don't record how strong
    the test was (trials / attacker rewrites) are treated as weak tests: fail closed on money."""
    limit, notes = int(row["limit"]), []
    trials, muts = row.get("trials"), row.get("mutations")
    if trials is None or muts is None:
        missing = [k for k, v in (("trials", trials), ("mutations", muts)) if v is None]
        notes.append(f"row doesn't record {' or '.join(missing)}: treated as a weak test")
    capped = cap_by_test_strength(limit, trials or 0, muts or 0, float(row.get("utility_under_attack", 0)))
    if capped != limit:
        notes.append(f"limit {limit} -> {capped} after the test-strength cap")
    return capped, notes


def to_usdc(limit: int, max_usdc: float = DEMO_MAX_USDC) -> float:
    """Scale a limit tier so the top tier equals max_usdc (pass 5000 for unscaled USDC)."""
    return round(limit * max_usdc / LIMIT_TIERS[-1], 6)


def scaled_tiers(max_usdc: float = DEMO_MAX_USDC) -> list[float]:
    return [to_usdc(t, max_usdc) for t in LIMIT_TIERS]


def apply(ledger, operator: str, agent: str, usdc: float) -> tuple[str, str]:
    """Approve the agent for exactly `usdc` from the operator's vault, or revoke if 0.
    Returns (action, signature)."""
    if usdc > 0:
        return "approve", ledger.approve(operator, agent, usdc)
    return "revoke", ledger.revoke(operator)
