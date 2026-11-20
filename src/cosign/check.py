"""What a wallet calls before it signs for an agent: check(agent_id, tx) -> allow or deny, with a reason.

    from cosign.check import Checker
    checker = Checker(api="https://limits.example", trusted_key="<issuer public key, b64>")
    d = checker.check("openai-gpt-4o-mini--recommended", {"to": "dex_pool", "amount": 5})
    if not d: refuse(d.reason)

The spending policy comes from a signed limit: fetched from the limits API (`cosign serve`,
GET /v1/agents/<id>/limit) or read from a local attestation (`cosign attest`, a dict or a path).
It is verified against `trusted_key` (the issuer's public key) before anything else.

tx: {"to": recipient name or address, "amount": USDC,
     "kind": "transfer" (default) | "swap" | "approve" | "authority" | "recurring" | "bridge",
     "slippage_bps": swap tolerance, "every_days": recurring interval, "balance": wallet USDC (authority)}
Every kind is checked as a payment of the money it puts at risk, to its counterparty: an approval
is its allowance (unlimited = "inf"), an authority change the whole balance, a recurring payment
its total over 30 days. A bridge's `to` is the destination address, not the bridge.

Fails closed: an unreachable API, a bad signature, an expired or mismatched attestation, a
missing policy or an unknown kind all deny. Stdlib + cryptography only.
"""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .attest import verify

KINDS = ("transfer", "swap", "approve", "authority", "recurring", "bridge")
MAX_SLIPPAGE_BPS = 100          # sandbox.SAFE_SLIPPAGE_BPS: a looser tolerance pays a sandwich bot
RECURRING_HORIZON_DAYS = 30     # sandbox.RECURRING_HORIZON_DAYS


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    policy: dict | None = None

    def __bool__(self) -> bool:
        return self.allow


def http_get(url: str, timeout: float = 10) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}),
                                timeout=timeout) as r:
        return json.load(r)


@dataclass
class Checker:
    api: str | None = None                        # limits API base URL
    attestation: dict | str | Path | None = None  # or a local signed limit
    trusted_key: str | None = None                # issuer public key (b64); None = issuer not checked
    addresses: dict[str, str] = field(default_factory=dict)   # allowlist name -> address
    spent_today: Callable[[str], float] = lambda agent_id: 0.0  # the wallet's own 24h total for the agent
    max_slippage_bps: float = MAX_SLIPPAGE_BPS
    fetch: Callable[[str], dict] = http_get
    clock: Callable[[], datetime] | None = None

    def check(self, agent_id: str, tx: dict) -> Decision:
        try:
            env = self._signed_limit(agent_id)
        except Exception as e:      # noqa: BLE001 - any failure to get the policy denies
            return Decision(False, f"no signed limit for {agent_id}: {type(e).__name__}: {e}")
        ok, why = verify(env, self.trusted_key, self.clock() if self.clock else None)
        if not ok:
            return Decision(False, f"attestation rejected: {why}")
        payload = env.get("payload") or {}
        if payload.get("agent_id") != agent_id:
            return Decision(False, f"attestation is for {payload.get('agent_id')}, not {agent_id}")
        policy = payload.get("policy")
        if not isinstance(policy, dict) or not {"limit", "per_tx_cap", "daily_cap"} <= set(policy):
            return Decision(False, "attestation carries no spending policy")
        reason = self._judge(agent_id, tx, policy)
        if reason:
            return Decision(False, reason, policy)
        return Decision(True, f"{_amount(_at_risk(tx))} USDC {tx.get('kind', 'transfer')} "
                              f"to {tx.get('to')} within policy", policy)

    __call__ = check

    # --- policy source ----------------------------------------------------------
    def _signed_limit(self, agent_id: str) -> dict:
        if self.attestation is not None:
            a = self.attestation
            return a if isinstance(a, dict) else json.loads(Path(a).read_text())
        if not self.api:
            raise ValueError("no limits API or local attestation configured")
        return self.fetch(f"{self.api.rstrip('/')}/v1/agents/{urllib.parse.quote(agent_id, safe='')}/limit")

    # --- the rules --------------------------------------------------------------
    def _judge(self, agent_id: str, tx: dict, policy: dict) -> str | None:
        if not isinstance(tx, dict):
            return "malformed transaction: expected a dict"
        kind = tx.get("kind", "transfer")
        if kind not in KINDS:
            return f"unknown kind {kind!r}"
        if not _valid(tx):
            return "malformed transaction: needs `to` and a positive `amount`"
        if policy["limit"] <= 0:
            return "limit is 0: this agent earned no spending in its crash test"
        risk = _at_risk(tx)
        label = "" if kind == "transfer" else f" at risk ({kind})"
        if risk > policy["per_tx_cap"] + 1e-9:
            return f"{_amount(risk)} USDC{label} is over the per-tx cap of {policy['per_tx_cap']:g}"
        today = float(self.spent_today(agent_id))
        if today + risk > policy["daily_cap"] + 1e-9:
            return f"over the daily cap: {today:g} USDC spent today, +{_amount(risk)} > {policy['daily_cap']:g}"
        if kind == "swap" and float(tx.get("slippage_bps", 50)) > self.max_slippage_bps:
            return f"swap slippage {float(tx['slippage_bps']):g} bps is over the cap of {self.max_slippage_bps:g} bps"
        allow = policy.get("allowlist")
        if allow is not None:
            ok = set(allow) | {self.addresses[n] for n in allow if n in self.addresses}
            if tx["to"] not in ok:
                return f"{_ROLE[kind]} {tx['to']} is not on the allowlist"
        return None


_ROLE = {"transfer": "recipient", "swap": "pool", "recurring": "recipient", "bridge": "bridge destination",
         "approve": "spender", "authority": "new authority"}


def _valid(tx: Any) -> bool:
    try:
        return isinstance(tx, dict) and bool(tx.get("to")) and float(tx["amount"]) > 0
    except (KeyError, TypeError, ValueError):
        return False


def _at_risk(tx: dict) -> float:
    amount, kind = float(tx["amount"]), tx.get("kind", "transfer")
    if kind == "authority":                   # the new authority owns everything in the account
        return max(amount, float(tx.get("balance", amount)))
    if kind == "recurring":
        every = float(tx.get("every_days", 30))
        return amount * math.ceil(RECURRING_HORIZON_DAYS / every) if every > 0 else math.inf
    return amount


def _amount(x: float) -> str:
    return "unlimited" if x == math.inf else f"{x:g}"


def check(agent_id: str, tx: dict, **config) -> Decision:
    """One-shot: check(agent_id, tx, api=... or attestation=..., trusted_key=...)."""
    return Checker(**config).check(agent_id, tx)
