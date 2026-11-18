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


# --- platform exports --------------------------------------------------------------
# Both platforms check one transaction at a time, so they get the per-tx cap and the allowlist.
# Neither policy language has a rolling daily total: daily_cap stays with Cosign (or the SPL
# delegation from `cosign grant`). Allowlist entries are sim names unless mapped to real addresses;
# both platforms compare the SPL transfer's destination, i.e. the recipient's USDC token account.
DEVNET_USDC = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"   # same default as solana_ledger
USDC_DECIMALS = 6
FORMATS = ("json", "privy", "turnkey")


def base_units(usdc: float) -> int:
    return int(round(usdc * 10 ** USDC_DECIMALS))


def resolve(allowlist: list[str] | None, addresses: dict[str, str] | None) -> tuple[list[str] | None, list[str]]:
    """Map allowlist names to addresses. Returns (allowlist, notes about names left unmapped)."""
    if allowlist is None:
        return None, []
    addresses = addresses or {}
    unmapped = [a for a in allowlist if a not in addresses]
    notes = [f"allowlist entry {a!r} is a test name, not an address: map it with --address {a}=<token account>"
             for a in unmapped]
    return [addresses.get(a, a) for a in allowlist], notes


def privy_policy(policy: dict, mint: str = DEVNET_USDC, addresses: dict[str, str] | None = None) -> tuple[dict, list[str]]:
    """Privy wallet policy (chain_type solana). Privy denies anything no rule allows, so a 0 limit
    exports as no rules."""
    allow, notes = resolve(policy["allowlist"], addresses)
    notes.append("privy: daily_cap is not enforced by this policy (per-transaction rules only)")
    src = "solana_token_program_instruction"
    conds = [{"field_source": src, "field": "TransferChecked.mint", "operator": "eq", "value": mint},
             {"field_source": src, "field": "TransferChecked.amount", "operator": "lte",
              "value": str(base_units(policy["per_tx_cap"]))}]
    if allow is not None:
        conds.append({"field_source": src, "field": "TransferChecked.destination", "operator": "in", "value": allow})
    rules = [] if policy["per_tx_cap"] <= 0 else [
        {"name": f"cosign: USDC up to {policy['per_tx_cap']:g} per transfer"
                 + (" to allowlisted recipients" if allow is not None else ""),
         "method": "signAndSendTransaction", "conditions": conds, "action": "ALLOW"}]
    return {"version": "1.0", "name": f"cosign {policy['agent_id']} (limit {policy['limit']})",
            "chain_type": "solana", "rules": rules}, notes


def turnkey_policy(policy: dict, mint: str = DEVNET_USDC, addresses: dict[str, str] | None = None,
                   signer: str | None = None) -> tuple[dict, list[str]]:
    """Turnkey createPolicy parameters. `signer` is the agent's Turnkey user id; without it the
    policy applies to every user in the organization. A 0 limit exports as a deny on all SPL transfers."""
    allow, notes = resolve(policy["allowlist"], addresses)
    notes.append("turnkey: daily_cap is not enforced by this policy (per-transaction conditions only)")
    if signer is None:
        notes.append("turnkey: no --signer given, so the policy has no consensus and applies to all users")
    if policy["per_tx_cap"] <= 0:
        effect, cond = "EFFECT_DENY", "solana.tx.spl_transfers.count() > 0"
    else:
        checks = [f"transfer.token_mint == '{mint}'", f"transfer.amount <= {base_units(policy['per_tx_cap'])}"]
        if allow is not None:
            checks.append("transfer.to in [" + ", ".join(f"'{a}'" for a in allow) + "]")
        effect = "EFFECT_ALLOW"
        cond = (f"solana.tx.spl_transfers.count() > 0 && solana.tx.transfers.count() == 0 && "
                f"solana.tx.spl_transfers.all(transfer, {' && '.join(checks)})")
    out = {"policyName": f"cosign {policy['agent_id']} (limit {policy['limit']})", "effect": effect,
           "condition": cond, "notes": f"cosign {policy['agent_hash']}, daily_cap {policy['daily_cap']:g} USDC"}
    if signer is not None:
        out["consensus"] = f"approvers.any(user, user.id == '{signer}')"
    return out, notes


def export(row: dict, fmt: str = "json", mint: str = DEVNET_USDC, addresses: dict[str, str] | None = None,
           signer: str | None = None) -> tuple[dict, list[str]]:
    policy = spending_policy(row)
    if fmt == "json":
        return policy, []
    if fmt == "privy":
        return privy_policy(policy, mint, addresses)
    if fmt == "turnkey":
        return turnkey_policy(policy, mint, addresses, signer)
    raise ValueError(f"unknown policy format {fmt} (have: {', '.join(FORMATS)})")
