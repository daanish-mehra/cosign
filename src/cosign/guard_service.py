"""cosign guard: a cosigner that can only say no.

The agent's vault is a 2-of-2 SPL multisig (agent + cosigner, see `cosign vault create`). The agent
builds and signs each transfer, then asks the guard for the second signature:

POST /v1/cosign  {"tx": <base64 tx, agent-signed>, "run_id": "<agent>/<preset>",
                  "tool_calls": [{"tool": "browse", "untrusted": true}, ...],   # this episode, oldest first
                  "attestation": <signed limit envelope, optional>}
             ->  {"decision": "approve" | "refuse" | "error", "reason": ..., "signature"?: ...}

Money moves it understands (exactly one per transaction, out of the vault):
  transfer     TransferChecked; the counterparty is the destination's owner
  swap         a transfer whose memo is "swap <SYMBOL> [slippage_bps=N]" (into a pool)
  bridge       a transfer to bridge_escrow; the counterparty is the destination in the memo
               "<chain>:<address>", not the bridge
  recurring    a transfer whose memo is "recurring every_days=N": judged by its total over 30 days
  approve      Approve / ApproveChecked: the delegate may pull the allowance (unlimited = over every cap)
  authority    SetAuthority on the vault's token account: the new authority gets the whole balance
Each is checked like a payment of the money it puts at risk, to its counterparty.

Checks, in order (the first failure refuses):
  transaction  one money move out of a 2-of-2 vault that includes this cosigner; only token /
               associated-token / memo / compute-budget instructions; every other required
               signature present and valid; the cosigner does not pay fees or rent
  attestation  signed by the trusted issuer, unexpired, for this run (sent along, or issued from
               the runs folder for run_id); its policy sets the caps below
  limit        the earned limit is above 0
  per-tx cap   amount <= policy per_tx_cap
  daily cap    cosigned out of this vault in the last 24h + amount <= policy daily_cap
  slippage     a swap's declared slippage <= the policy's max_slippage_bps (default 100)
  taint        if any tool call this episode read untrusted input, the counterparty must be on the
               allowlist (the policy's, or the guard's --allow list when the policy has none)
  allowlist    if the policy has an allowlist, the counterparty must be on it
If every check passes the guard adds its signature and submits. It never signs anything else, and
never moves money on its own: the agent's signature is always required too.

Every decision is a JSON line in logs/guard.log; the daily totals are rebuilt from it on start.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .attest import agent_id, preset_of, public_key_b64, verify
from .policy import signed_limit

DAY = timedelta(hours=24)
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
APPROVE, SET_AUTHORITY, TRANSFER_CHECKED, APPROVE_CHECKED = 4, 6, 12, 13
U64_MAX = 2 ** 64 - 1
AUTHORITY_TYPES = {2: "owner", 3: "close"}      # token-account authorities that hand over the balance
BRIDGE = "bridge_escrow"                        # sandbox.BRIDGE
_SWAP = re.compile(r"^swap (\S+)(?:.*\bslippage_bps=(\d+(?:\.\d+)?))?")
_RECURRING = re.compile(r"^recurring\b.*\bevery_days=(\d+(?:\.\d+)?)")
_BRIDGE_TO = re.compile(r"^([A-Za-z]+):(\S+)$")


class Refuse(Exception):
    pass


_ROLE = {"transfer": "recipient", "swap": "recipient", "recurring": "recipient", "bridge": "bridge destination",
         "approve": "spender", "authority": "new authority"}


@dataclass
class Move:
    kind: str           # transfer | swap | bridge | recurring | approve | authority
    vault: str          # source token account
    multisig: str
    recipient: str      # the counterparty: destination owner, bridge destination, delegate or new authority
    amount: float       # USDC put at risk (a recurring payment's total, an allowance, the whole balance)
    detail: dict        # slippage_bps, chain, every_days, allowance, ...


def run_key_of(row: dict) -> str:
    return row.get("run") or f"{row['agent']}/{preset_of(row)}"


def runs_lookup(runs_dir: str | Path) -> Callable[[str], dict | None]:
    """run id ("<agent>/<preset>", or an agent id) -> the newest results row for it in runs/."""
    from .api import latest_runs

    def find(run_id: str) -> dict | None:
        for aid, hit in latest_runs(Path(runs_dir)).items():
            if run_id in (aid, run_key_of(hit["row"])):
                return hit["row"]
        return None
    return find


class Cosigner:
    def __init__(self, ledger, cosigner: str, issuer_key, lookup: Callable[[str], dict | None],
                 log: str | Path = "logs/guard.log", allow: list[str] | None = None,
                 clock: Callable[[], datetime] | None = None, max_slippage_bps: float | None = 100):
        self.ledger, self.cosigner, self.issuer_key, self.lookup = ledger, cosigner, issuer_key, lookup
        self.max_slippage_bps = max_slippage_bps
        self.log = Path(log)
        self.allow = list(allow or [])
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.pubkey = str(ledger.pubkey(cosigner))
        self.spent: list[tuple[datetime, str, float]] = self._replay()   # (time, multisig, amount) cosigned

    # --- the decision ---------------------------------------------------------
    def decide(self, req: dict) -> dict:
        record: dict = {"run_id": req.get("run_id")}
        calls = [c for c in req.get("tool_calls") or [] if isinstance(c, dict)]
        tainted = sorted({str(c.get("tool")) for c in calls if c.get("untrusted")})
        record["untrusted_tools"] = tainted
        try:
            tx = self._parse(req.get("tx"))
            t = self._move(tx)
            record |= {"kind": t.kind, "vault": t.vault, "recipient": t.recipient,
                       "recipient_name": self.ledger.name_of(t.recipient), "amount": t.amount, **t.detail}
            policy = self._policy(req)
            record["limit"] = policy["limit"]
            self._check(t, policy, tainted)
        except Refuse as r:
            return self._decide(record, "refuse", str(r))
        try:
            tx.partial_sign([self.ledger.keys.keypair(self.cosigner)], tx.message.recent_blockhash)
            sig = self.ledger.rpc("sendTransaction", [base64.b64encode(bytes(tx)).decode(),
                                                      {"encoding": "base64", "preflightCommitment": "confirmed"}])
            self.ledger._confirm(sig)
        except Exception as e:   # signed but didn't land: not counted toward the daily cap
            return self._decide(record, "error", f"cosigned but not confirmed: {type(e).__name__}: {str(e)[:200]}")
        self.spent.append((self.clock(), t.multisig, t.amount))
        what = {"transfer": "", "swap": "swap: ", "bridge": "bridge: ", "recurring": "recurring: ",
                "approve": "allowance: ", "authority": "authority: "}[t.kind]
        return self._decide(record | {"signature": sig, "multisig": t.multisig}, "approve",
                            f"{what}{t.amount:g} USDC to {record['recipient_name']} within policy", sig)

    def _check(self, t: Move, policy: dict, tainted: list[str]) -> None:
        name = self.ledger.name_of(t.recipient)
        shown = "unlimited" if t.amount == float("inf") else f"{t.amount:g}"
        if policy["limit"] <= 0:
            raise Refuse("limit is 0: this agent earned no spending in its crash test")
        if t.amount > policy["per_tx_cap"] + 1e-9:
            what = "" if t.kind == "transfer" else f" at risk ({t.kind})"
            raise Refuse(f"{shown} USDC{what} is over the per-tx cap of {policy['per_tx_cap']:g}")
        since = self.clock() - DAY
        today = sum(a for ts, ms, a in self.spent if ms == t.multisig and ts > since)
        if today + t.amount > policy["daily_cap"] + 1e-9:
            raise Refuse(f"over the daily cap: {today:g} USDC cosigned in the last 24h, "
                         f"+{shown} > {policy['daily_cap']:g}")
        cap = policy.get("max_slippage_bps", self.max_slippage_bps)
        slip = t.detail.get("slippage_bps")
        if t.kind == "swap" and cap is not None and slip is not None and slip > cap:
            raise Refuse(f"swap slippage {slip:g} bps is over the cap of {cap:g} bps")
        allowlist = policy.get("allowlist")
        allowed = self._resolve(allowlist if allowlist is not None else self.allow)
        if tainted and t.recipient not in allowed:
            raise Refuse(f"untrusted input was read this episode ({', '.join(tainted)}) and "
                         f"{_ROLE[t.kind]} {name} is not on the allowlist")
        if allowlist is not None and t.recipient not in allowed:
            raise Refuse(f"{_ROLE[t.kind]} {name} is not on the allowlist")

    # --- attestation + policy --------------------------------------------------
    def _policy(self, req: dict) -> dict:
        run_id = req.get("run_id")
        row = self.lookup(run_id) if run_id else None
        env = req.get("attestation")
        if env is None:
            if row is None:
                raise Refuse(f"no attestation sent and no crash-test run {run_id!r} on file")
            env = signed_limit(row, self.issuer_key, self.clock())
        ok, reason = verify(env, public_key_b64(self.issuer_key), self.clock())
        if not ok:
            raise Refuse(f"attestation rejected: {reason}")
        payload = env["payload"]
        if row is not None and payload.get("agent_id") != agent_id(row):
            raise Refuse(f"attestation is for {payload.get('agent_id')}, not run {run_id}")
        policy = payload.get("policy")
        if not isinstance(policy, dict) or not {"limit", "per_tx_cap", "daily_cap"} <= set(policy):
            raise Refuse("attestation carries no spending policy (use the signed limit from /v1/agents/<id>/limit)")
        return policy

    def _resolve(self, entries: list[str]) -> set[str]:
        """Allowlist entries -> owner pubkeys. Names resolve only if the keystore already has them."""
        from solders.pubkey import Pubkey
        out = set()
        for e in entries:
            if len(e) >= 32:
                try:
                    out.add(str(Pubkey.from_string(e)))
                    continue
                except ValueError:
                    pass
            if e in self.ledger.keys.names():
                out.add(str(self.ledger.keys.keypair(e).pubkey()))
        return out

    # --- transaction decoding ----------------------------------------------------
    def _parse(self, b64):
        from solders.transaction import Transaction
        try:
            return Transaction.from_bytes(base64.b64decode(b64, validate=True))
        except Exception:
            raise Refuse("malformed transaction: expected a base64 serialized Solana transaction")

    def _move(self, tx) -> Move:
        from solders.pubkey import Pubkey
        from spl.memo.constants import MEMO_PROGRAM_ID
        from spl.token.constants import ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID
        from spl.token.instructions import get_associated_token_address

        msg = tx.message
        keys = [str(k) for k in msg.account_keys]
        n_sign = msg.header.num_required_signatures
        if self.pubkey not in keys[:n_sign]:
            raise Refuse("this cosigner is not a required signer of the transaction")
        if keys[0] == self.pubkey:
            raise Refuse("the cosigner does not pay fees: make the agent the fee payer")
        data = tx.message_data()
        for i in range(n_sign):
            if keys[i] != self.pubkey and not tx.signatures[i].verify(Pubkey.from_string(keys[i]), data):
                raise Refuse(f"missing or invalid signature from {self.ledger.name_of(keys[i])}")

        moves, created, memos = [], {}, []
        for ix in msg.instructions:
            prog = keys[ix.program_id_index]
            acc = [keys[i] for i in ix.accounts]
            raw = bytes(ix.data)
            op = raw[:1]
            if prog == str(TOKEN_PROGRAM_ID) and op == bytes([TRANSFER_CHECKED]) and len(raw) == 10 and len(acc) >= 4:
                moves.append(("transfer", acc, raw))
            elif prog == str(TOKEN_PROGRAM_ID) and op == bytes([APPROVE_CHECKED]) and len(raw) == 10 and len(acc) >= 4:
                moves.append(("approve", acc, raw))
            elif prog == str(TOKEN_PROGRAM_ID) and op == bytes([APPROVE]) and len(raw) == 9 and len(acc) >= 3:
                src, delegate, owner, *rest = acc     # same shape as ApproveChecked, minus the mint
                moves.append(("approve", [src, self.ledger.mint, delegate, owner, *rest], raw + bytes([6])))
            elif prog == str(TOKEN_PROGRAM_ID) and op == bytes([SET_AUTHORITY]) and len(acc) >= 2:
                moves.append(("authority", acc, raw))
            elif prog == str(ASSOCIATED_TOKEN_PROGRAM_ID) and raw in (b"", b"\x01") and len(acc) >= 4:
                if acc[0] == self.pubkey:
                    raise Refuse("the cosigner does not pay account rent")
                created[acc[1]] = (acc[2], acc[3])     # ata -> (owner, mint)
            elif prog == str(MEMO_PROGRAM_ID):
                memos.append(raw.decode("utf-8", "replace"))
            elif prog == COMPUTE_BUDGET:
                continue
            else:
                raise Refuse(f"instruction not allowed (program {prog}): the guard only cosigns USDC money moves "
                             "(transfers, approvals, authority changes)")
        if len(moves) != 1:
            raise Refuse(f"expected exactly one money move, found {len(moves)}")
        kind, acc, raw = moves[0]
        memo = " ".join(memos).strip()

        if kind == "authority":
            src, auth, *members = acc
            vault = self._vault(src, auth, self.ledger.mint)
            atype = raw[1] if len(raw) > 1 else None
            if atype not in AUTHORITY_TYPES:
                raise Refuse(f"authority type {atype} not allowed on the vault")
            if len(raw) != 35 or raw[2] != 1:
                raise Refuse("removing the vault's authority is not allowed")
            new = str(Pubkey.from_bytes(raw[3:35]))
            at_risk = float((vault.get("tokenAmount") or {}).get("uiAmountString") or 0)
            return Move("authority", src, auth, new, at_risk, {"authority_type": AUTHORITY_TYPES[atype]})

        src, mint, other, auth, *members = acc
        units, decimals = int.from_bytes(raw[1:9], "little"), raw[9]
        if mint != self.ledger.mint or decimals != 6:
            raise Refuse(f"not a USDC {'approval' if kind == 'approve' else 'transfer'} (mint {mint})")
        self._vault(src, auth, mint)
        if kind == "approve":
            amount = float("inf") if units == U64_MAX else units / 10 ** 6
            return Move("approve", src, auth, other, amount,
                        {"allowance": "unlimited" if amount == float("inf") else amount})

        dst = other
        if dst in created:
            owner, ata_mint = created[dst]
            if ata_mint != mint or str(get_associated_token_address(Pubkey.from_string(owner),
                                                                    Pubkey.from_string(mint))) != dst:
                raise Refuse("destination account doesn't match the account the transaction creates")
        else:
            owner = (self._account(dst).get("info") or {}).get("owner")
            if not owner:
                raise Refuse("unknown destination token account")
        amount = units / 10 ** 6
        if self.ledger.name_of(owner) == BRIDGE:
            m = _BRIDGE_TO.match(memo)
            if not m:
                raise Refuse('bridge transfer without a destination: memo must be "<chain>:<address>"')
            return Move("bridge", src, auth, self._counterparty(m.group(2)), amount, {"chain": m.group(1)})
        if m := _RECURRING.match(memo):
            from .sandbox import recurring_total
            every = float(m.group(1))
            if every <= 0:
                raise Refuse("recurring payment needs every_days > 0")
            return Move("recurring", src, auth, owner, recurring_total(amount, every),
                        {"every_days": every, "instalment": amount})
        if m := _SWAP.match(memo):
            detail = {"symbol": m.group(1)}
            if m.group(2) is not None:
                detail["slippage_bps"] = float(m.group(2))
            return Move("swap", src, auth, owner, amount, detail)
        return Move("transfer", src, auth, owner, amount, {})

    def _vault(self, src: str, auth: str, mint: str) -> dict:
        """The token account is the vault: owned by a 2-of-2 multisig this cosigner is in."""
        ms = self._account(auth)
        if ms.get("type") != "multisig" or ms["info"]["numRequiredSigners"] != 2 \
                or self.pubkey not in ms["info"]["signers"][: ms["info"]["numValidSigners"]]:
            raise Refuse("source is not a 2-of-2 vault that this cosigner belongs to")
        info = self._account(src).get("info") or {}
        if info.get("owner") != auth or info.get("mint", mint) != mint:
            raise Refuse("source token account is not owned by the vault multisig")
        return info

    def _counterparty(self, who: str) -> str:
        """A pubkey, or a name the keystore already knows (never creates keys); else kept as given."""
        resolved = self._resolve([who])
        return next(iter(resolved)) if resolved else who

    def _account(self, addr: str) -> dict:
        res = self.ledger.rpc("getAccountInfo", [addr, {"encoding": "jsonParsed", "commitment": "confirmed"}])
        if not res or not res.get("value"):
            return {}
        return res["value"]["data"].get("parsed") or {}

    # --- log ---------------------------------------------------------------------
    def _decide(self, record: dict, decision: str, reason: str, sig: str | None = None) -> dict:
        line = {"ts": self.clock().isoformat(), "decision": decision, "reason": reason, **record}
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log, "a") as f:
            f.write(json.dumps(line) + "\n")
        out = {"decision": decision, "reason": reason}
        if sig:
            out["signature"] = sig
        return out

    def _replay(self) -> list[tuple[datetime, str, float]]:
        out = []
        if not self.log.exists():
            return out
        for ln in self.log.read_text().splitlines():
            try:
                r = json.loads(ln)
                if r.get("decision") == "approve":
                    out.append((datetime.fromisoformat(r["ts"]), r["multisig"], float(r["amount"])))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue
        return out


def create_app(cosigner: Cosigner):
    from fastapi import Body, FastAPI

    app = FastAPI(title="cosign guard", version="1")

    @app.post("/v1/cosign")
    def cosign(req: dict = Body(...)):
        return cosigner.decide(req)

    @app.get("/v1/health")
    def health():
        return {"cosigner": cosigner.pubkey, "issuer": public_key_b64(cosigner.issuer_key)}

    return app
