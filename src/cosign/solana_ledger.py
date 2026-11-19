"""SolanaLedger: the Ledger interface (balance, transfer, history) backed by devnet USDC.

Same names the sandbox uses ("agent_wallet", "dex_pool", "attacker_wallet", ...) map to local
keypairs, created on first use and kept in a JSON file OUTSIDE the repo
(default ~/.config/cosign/devnet-keypairs.json, override with COSIGN_KEYPAIRS).

A "treasury" keypair pays every fee and tops wallets up via fund(); it is the only wallet that
needs devnet SOL (airdrop) and devnet USDC (faucet.circle.com). Every other wallet is cosign's,
so sweep() can pull stolen/swapped USDC back to the treasury after a run.

Network access is one synchronous JSON-RPC callable (`rpc(method, params) -> result`), so tests
swap in a fake. solana-py >= 0.42 ships only an async client; keys, instructions and signing come
from solders + spl (installed with `pip install -e .[solana]`).
"""

from __future__ import annotations

import base64
import json
import os
import stat
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .ledger import InsufficientFunds, Refused, Transfer

DEVNET_RPC = "https://api.devnet.solana.com"
DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
DEVNET_USDC = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"   # Circle's devnet USDC mint
USDC_DECIMALS = 6
TREASURY = "treasury"
VAULT_PREFIX = "vault:"        # keystore name of an agent's multisig account: "vault:<agent>"
DEFAULT_KEYPAIRS = Path("~/.config/cosign/devnet-keypairs.json")

Rpc = Callable[[str, list], Any]


class RpcError(Exception):
    pass


def http_guard(url: str, timeout: float = 60) -> Callable[[dict], dict]:
    """POST cosign requests to a running `cosign guard serve` (url like http://127.0.0.1:8100)."""
    def call(req: dict) -> dict:
        body = json.dumps(req).encode()
        r = urllib.request.Request(url.rstrip("/") + "/v1/cosign", body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.load(resp)
    return call


def http_rpc(url: str, timeout: float = 30, retries: int = 6, sleep: Callable[[float], None] = time.sleep) -> Rpc:
    """JSON-RPC over HTTP; backs off and retries on 429 (the public devnet endpoint rate-limits hard)."""
    import urllib.error

    def call(method: str, params: list) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    reply = json.load(r)
                break
            except urllib.error.HTTPError as e:
                if e.code != 429 or attempt == retries:
                    raise
                sleep(min(0.5 * 2 ** attempt, 8))
        if "error" in reply:
            raise RpcError(f"{method}: {reply['error']}")
        return reply.get("result")
    return call


# --- keypairs ----------------------------------------------------------------
class KeyStore:
    """{name: [64 secret-key bytes]} in a 0600 file; names not seen before get a fresh keypair."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or os.environ.get("COSIGN_KEYPAIRS") or DEFAULT_KEYPAIRS).expanduser()
        self._raw: dict[str, list[int]] = json.loads(self.path.read_text()) if self.path.exists() else {}

    def keypair(self, name: str):
        from solders.keypair import Keypair
        if name not in self._raw:
            self._raw[name] = list(bytes(Keypair()))
            self._save()
        return Keypair.from_bytes(bytes(self._raw[name]))

    def names(self) -> list[str]:
        return list(self._raw)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._raw, f)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.path)


# --- parsing (shared with the outflow watcher) --------------------------------
def parse_usdc_transfers(tx: dict | None, mint: str = DEVNET_USDC) -> list[dict]:
    """USDC transfers in a jsonParsed getTransaction result, with token accounts resolved to owners."""
    if not tx or (tx.get("meta") or {}).get("err") is not None:
        return []
    msg, meta = tx["transaction"]["message"], tx.get("meta") or {}
    keys = [k["pubkey"] if isinstance(k, dict) else k for k in msg.get("accountKeys", [])]
    owners: dict[str, str] = {}
    mints: dict[str, str] = {}
    for b in (meta.get("preTokenBalances") or []) + (meta.get("postTokenBalances") or []):
        acct = keys[b["accountIndex"]]
        if b.get("owner"):
            owners[acct] = b["owner"]
        mints[acct] = b.get("mint", "")
    ixs = list(msg.get("instructions", []))
    for inner in meta.get("innerInstructions") or []:
        ixs += inner.get("instructions", [])
    memo = next((ix["parsed"] for ix in ixs if ix.get("program") == "spl-memo"
                 and isinstance(ix.get("parsed"), str)), "")
    out = []
    for ix in ixs:
        p = ix.get("parsed")
        if ix.get("program") != "spl-token" or not isinstance(p, dict):
            continue
        info = p.get("info", {})
        if p.get("type") == "transferChecked" and info.get("mint") == mint:
            amount = float(info["tokenAmount"]["uiAmountString"])
        elif p.get("type") == "transfer" and mints.get(info.get("source")) == mint:
            amount = int(info["amount"]) / 10 ** USDC_DECIMALS
        else:
            continue
        src, dst = info["source"], info["destination"]
        out.append({"signature": tx["transaction"]["signatures"][0], "slot": tx.get("slot"),
                    "block_time": tx.get("blockTime"),
                    "from": owners.get(src) or info.get("authority") or src,
                    "to": owners.get(dst, dst), "amount": amount, "memo": memo})
    return out


# --- the ledger ---------------------------------------------------------------
@dataclass
class SolanaLedger:
    rpc: Rpc
    keys: KeyStore
    mint: str = DEVNET_USDC
    fee_payer: str = TREASURY      # wallet that pays fees and new token-account rent
    confirm_timeout: float = 60.0
    poll: float = 1.0
    transfers: list[Transfer] = field(default_factory=list)   # this session's transfers, like SimLedger
    sent_messages: set[bytes] = field(default_factory=set, repr=False)  # share across sessions to catch repeats
    # guarded mode (use_vault): agent name -> (multisig name, cosigner name), the guard, and its run id
    vaults: dict[str, tuple[str, str]] = field(default_factory=dict)
    guard: Callable[[dict], dict] | None = field(default=None, repr=False)
    run_id: str | None = None
    refusals: list[dict] = field(default_factory=list)   # {sender, recipient, amount, reason}
    context_calls: int = 20                               # last N tool calls sent with each request
    _agent: Any = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "SolanaLedger":
        """SOLANA_RPC_URL (default public devnet), COSIGN_KEYPAIRS, COSIGN_USDC_MINT. Devnet only."""
        rpc = http_rpc(os.environ.get("SOLANA_RPC_URL") or DEVNET_RPC)
        ledger = cls(rpc, KeyStore(), os.environ.get("COSIGN_USDC_MINT") or DEVNET_USDC)
        ledger.check_devnet()
        return ledger

    def check_devnet(self) -> None:
        genesis = self.rpc("getGenesisHash", [])
        if genesis != DEVNET_GENESIS:
            raise RuntimeError(f"refusing to run: RPC endpoint is not Solana devnet (genesis {genesis})")

    # --- addresses ---
    def pubkey(self, address: str):
        from solders.pubkey import Pubkey
        try:
            if len(address) >= 32:
                return Pubkey.from_string(address)
        except ValueError:
            pass
        return self.keys.keypair(address).pubkey()

    def token_account(self, address: str):
        from solders.pubkey import Pubkey
        from spl.token.instructions import get_associated_token_address
        return get_associated_token_address(self.pubkey(address), Pubkey.from_string(self.mint))

    def name_of(self, pubkey: str) -> str:
        for n in self.keys.names():
            if str(self.keys.keypair(n).pubkey()) == pubkey:
                return n
        return pubkey

    # --- Ledger interface ---
    def balance(self, address: str) -> float:
        if address in self.vaults:            # guarded mode: the agent's money is its vault
            address = self.vaults[address][0]
        res = self.rpc("getTokenAccountsByOwner", [str(self.pubkey(address)), {"mint": self.mint},
                                                   {"encoding": "jsonParsed", "commitment": "confirmed"}])
        return sum(float(a["account"]["data"]["parsed"]["info"]["tokenAmount"]["uiAmountString"])
                   for a in res["value"])

    def transfer(self, sender: str, recipient: str, amount: float, memo: str = "") -> Transfer:
        if sender in self.vaults and self.guard is not None:
            sig = self._send_guarded(sender, recipient, amount, memo)
        else:
            sig = self._send(sender, recipient, amount, memo)
        t = Transfer(sender, recipient, amount, memo, sig)
        self.transfers.append(t)
        return t

    def history(self, address: str, limit: int = 25) -> list[Transfer]:
        sigs = self.rpc("getSignaturesForAddress", [str(self.token_account(address)),
                                                    {"limit": limit, "commitment": "confirmed"}])
        out: list[Transfer] = []
        for s in sigs or []:
            if s.get("err") is not None:
                continue
            tx = self.rpc("getTransaction", [s["signature"], {"encoding": "jsonParsed", "commitment": "confirmed",
                                                              "maxSupportedTransactionVersion": 0}])
            for t in parse_usdc_transfers(tx, self.mint):
                out.append(Transfer(self.name_of(t["from"]), self.name_of(t["to"]), t["amount"],
                                    t["memo"], t["signature"]))
        return out

    # --- devnet housekeeping ---
    def fund(self, address: str, amount: float) -> None:
        """Top `address` up to `amount` USDC from the treasury (not recorded as an agent transfer)."""
        if address in self.vaults:
            address = self.vaults[address][0]
        short = amount - self.balance(address)
        if short <= 1e-9:
            return
        treasury = str(self.pubkey(TREASURY))
        if self.rpc("getBalance", [treasury, {"commitment": "confirmed"}])["value"] < 10_000_000:
            raise InsufficientFunds(f"treasury {treasury} needs devnet SOL for fees: solana airdrop 1 {treasury} -u devnet")
        if self.balance(TREASURY) + 1e-9 < short:
            raise InsufficientFunds(f"treasury {treasury} needs {short:g} more devnet USDC: "
                                    f"https://faucet.circle.com (Solana Devnet)")
        self._send(TREASURY, address, short, "cosign fund")

    def sweep(self) -> float:
        """Move USDC from every cosign wallet back to the treasury. Returns the amount swept."""
        total = 0.0
        for n in self.keys.names():
            if n.startswith(VAULT_PREFIX):
                continue   # multisig vaults need both signers; their key can't move funds
            if n != TREASURY and (b := self.balance(n)) > 0:
                self._send(n, TREASURY, b, "cosign sweep")
                total += b
        return total

    # --- spend limit enforced on chain: SPL token delegation --------------------
    # The operator owns the vault (its USDC token account). The agent key is approved as the
    # vault's delegate for exactly the earned limit, so the token program itself refuses any
    # spend beyond it, whatever the agent's software does. One delegate per account; a new
    # approve replaces the old allowance, revoke clears it.
    def vault(self, owner: str) -> dict | None:
        """{'address', 'balance', 'delegate', 'delegated'} for the owner's USDC account, or None."""
        acct = str(self.token_account(owner))
        res = self.rpc("getAccountInfo", [acct, {"encoding": "jsonParsed", "commitment": "confirmed"}])
        if not res or not res.get("value"):
            return None
        info = res["value"]["data"]["parsed"]["info"]
        delegated = info.get("delegatedAmount") or {}
        return {"address": acct, "balance": float(info["tokenAmount"]["uiAmountString"]),
                "delegate": info.get("delegate"),
                "delegated": float(delegated.get("uiAmountString", 0)) if info.get("delegate") else 0.0}

    def approve(self, owner: str, delegate: str, amount: float) -> str:
        from solders.pubkey import Pubkey
        from spl.token.constants import TOKEN_PROGRAM_ID
        from spl.token.instructions import approve_checked
        from spl.token.models import ApproveCheckedParams
        if amount <= 0:
            raise ValueError("allowance must be positive; use revoke() for 0")
        ix = approve_checked(ApproveCheckedParams(
            program_id=TOKEN_PROGRAM_ID, source=self.token_account(owner), mint=Pubkey.from_string(self.mint),
            delegate=self.pubkey(delegate), owner=self.pubkey(owner),
            amount=round(amount * 10 ** USDC_DECIMALS), decimals=USDC_DECIMALS))
        return self._submit([ix], [owner])

    def revoke(self, owner: str) -> str:
        from spl.token.constants import TOKEN_PROGRAM_ID
        from spl.token.instructions import revoke
        from spl.token.models import RevokeParams
        ix = revoke(RevokeParams(program_id=TOKEN_PROGRAM_ID, account=self.token_account(owner),
                                 owner=self.pubkey(owner)))
        return self._submit([ix], [owner])

    def spend_as_delegate(self, delegate: str, owner: str, recipient: str, amount: float,
                          memo: str = "") -> Transfer:
        """Pay from the owner's vault using the delegate's allowance. No off-chain balance check:
        the token program accepts it only within the allowance (else RpcError from preflight)."""
        sig = self._submit(self._transfer_ixs(delegate, recipient, amount, memo, source_owner=owner), [delegate])
        t = Transfer(delegate, recipient, amount, memo, sig)
        self.transfers.append(t)
        return t

    # --- 2-of-2 vault: SPL Token multisig (agent + cosigner) ---------------------
    # The vault is a USDC token account owned by an SPL multisig with m=2 over the agent key and
    # a cosigner key. Every outflow needs both signatures, so the cosigner (cosign guard) can veto
    # any transfer but can never move money alone.
    @staticmethod
    def multisig_name(agent: str) -> str:
        return VAULT_PREFIX + agent

    def create_multisig_vault(self, agent: str, cosigner: str) -> dict:
        """Create (or confirm) the agent's multisig and its USDC token account. The fee payer
        pays rent. Idempotent: an existing vault is checked, not recreated."""
        from solders.system_program import CreateAccountParams, create_account
        from spl.token.constants import MULTISIG_LEN, TOKEN_PROGRAM_ID
        from spl.token.instructions import create_idempotent_associated_token_account, initialize_multisig
        from spl.token.models import InitializeMultisigParams
        from solders.pubkey import Pubkey

        if agent == cosigner:
            raise ValueError("agent and cosigner must be different keys")
        name = self.multisig_name(agent)
        multisig = self.keys.keypair(name).pubkey()
        want = sorted([str(self.pubkey(agent)), str(self.pubkey(cosigner))])
        existing = self.multisig_vault(agent)
        if existing is not None:
            if existing["m"] != 2 or sorted(existing["signers"]) != want:
                raise RuntimeError(f"{multisig} already exists with other signers; refusing to reuse it")
            if existing["token_account_exists"]:
                return existing | {"created": False}
            ixs = []
        else:
            rent = self.rpc("getMinimumBalanceForRentExemption", [MULTISIG_LEN])
            ixs = [create_account(CreateAccountParams(from_pubkey=self.pubkey(self.fee_payer), to_pubkey=multisig,
                                                      lamports=rent, space=MULTISIG_LEN, owner=TOKEN_PROGRAM_ID)),
                   initialize_multisig(InitializeMultisigParams(
                       program_id=TOKEN_PROGRAM_ID, multisig=multisig, m=2,
                       signers=[self.pubkey(agent), self.pubkey(cosigner)]))]
        ixs.append(create_idempotent_associated_token_account(self.pubkey(self.fee_payer), multisig,
                                                              Pubkey.from_string(self.mint)))
        sig = self._submit(ixs, [name] if existing is None else [])
        return (self.multisig_vault(agent) or {}) | {"created": True, "signature": sig}

    def multisig_vault(self, agent: str) -> dict | None:
        """{'multisig', 'token_account', 'm', 'signers', 'balance', 'token_account_exists'} or None."""
        name = self.multisig_name(agent)
        if name not in self.keys.names():
            return None
        multisig = str(self.keys.keypair(name).pubkey())
        res = self.rpc("getAccountInfo", [multisig, {"encoding": "jsonParsed", "commitment": "confirmed"}])
        if not res or not res.get("value"):
            return None
        info = res["value"]["data"]["parsed"]["info"]
        acct = str(self.token_account(name))
        tok = self.rpc("getAccountInfo", [acct, {"encoding": "jsonParsed", "commitment": "confirmed"}])
        exists = bool(tok and tok.get("value"))
        bal = float(tok["value"]["data"]["parsed"]["info"]["tokenAmount"]["uiAmountString"]) if exists else 0.0
        return {"multisig": multisig, "token_account": acct, "m": info["numRequiredSigners"],
                "signers": list(info["signers"][: info["numValidSigners"]]), "balance": bal,
                "token_account_exists": exists}

    def fund_vault(self, agent: str, usdc: float) -> float:
        """Top the agent's vault up to `usdc` from the treasury. Returns the new balance."""
        if self.multisig_vault(agent) is None:
            raise RuntimeError(f"no vault for {agent}: run `cosign vault create` first")
        self.fund(self.multisig_name(agent), usdc)
        return self.balance(self.multisig_name(agent))

    # --- guarded mode: vault transfers go to cosign guard for the second signature ---
    def use_vault(self, agent: str, cosigner: str, guard: Callable[[dict], dict], run_id: str) -> None:
        """From now on `agent`'s transfers come out of its 2-of-2 vault: built here, signed by the
        agent, then sent to `guard` (a Cosigner.decide, or http_guard(url)) which cosigns and submits
        or refuses. The agent pays the fee; the cosigner never does."""
        if self.fee_payer == cosigner:
            raise ValueError("the cosigner can't be the fee payer in guarded mode")
        self.vaults[agent] = (self.multisig_name(agent), cosigner)
        self.guard, self.run_id = guard, run_id

    def bind_agent(self, agent) -> None:
        """Called by Agent: its tool calls so far are the context sent with each cosign request."""
        self._agent = agent

    def episode_context(self) -> list[dict]:
        steps = getattr(self._agent, "steps", None) or []
        return [{"tool": s["tool"], "untrusted": bool(s.get("untrusted"))}
                for s in steps[-self.context_calls:] if s.get("tool") != "final"]

    def _send_guarded(self, sender: str, recipient: str, amount: float, memo: str) -> str:
        from solders.transaction import Transaction
        if amount <= 0:
            raise ValueError("amount must be positive")
        multisig, cosigner = self.vaults[sender]
        have = self.balance(multisig)
        if have + 1e-9 < amount:
            raise InsufficientFunds(f"{sender}'s vault has {have}, tried {amount}")
        ixs = self._transfer_ixs(multisig, recipient, amount, memo, signers=[sender, cosigner])
        msg = self._message(ixs)
        tx = Transaction.new_unsigned(msg)
        own = {self.fee_payer, sender}
        tx.partial_sign([self.keys.keypair(n) for n in sorted(own)], msg.recent_blockhash)
        reply = self.guard({"tx": base64.b64encode(bytes(tx)).decode(), "run_id": self.run_id,
                            "tool_calls": self.episode_context()})
        decision, reason = reply.get("decision"), reply.get("reason", "")
        if decision == "approve" and reply.get("signature"):
            return reply["signature"]
        if decision == "refuse":
            self.refusals.append({"sender": sender, "recipient": recipient, "amount": amount, "reason": reason})
            raise Refused(reason)
        raise RpcError(f"cosign guard: {decision}: {reason}")

    # --- transactions ---
    def _send(self, sender: str, recipient: str, amount: float, memo: str) -> str:
        if amount <= 0:
            raise ValueError("amount must be positive")
        have = self.balance(sender)
        if have + 1e-9 < amount:
            raise InsufficientFunds(f"{sender} has {have}, tried {amount}")
        return self._submit(self._transfer_ixs(sender, recipient, amount, memo), [sender])

    def _transfer_ixs(self, authority: str, recipient: str, amount: float, memo: str,
                      source_owner: str | None = None, signers: list[str] | None = None) -> list:
        """`signers`: when `authority` is a multisig, the member keys that will sign (memo signer = first)."""
        from solders.pubkey import Pubkey
        from spl.memo.constants import MEMO_PROGRAM_ID
        from spl.memo.instructions import create_memo
        from spl.memo.models import MemoParams
        from spl.token.constants import TOKEN_PROGRAM_ID
        from spl.token.instructions import create_idempotent_associated_token_account, transfer_checked
        from spl.token.models import TransferCheckedParams

        if amount <= 0:
            raise ValueError("amount must be positive")
        mint = Pubkey.from_string(self.mint)
        auth = self.pubkey(authority)
        ixs = [
            create_idempotent_associated_token_account(self.pubkey(self.fee_payer), self.pubkey(recipient), mint),
            transfer_checked(TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID, source=self.token_account(source_owner or authority), mint=mint,
                dest=self.token_account(recipient), owner=auth, amount=round(amount * 10 ** USDC_DECIMALS),
                decimals=USDC_DECIMALS, signers=[self.pubkey(n) for n in signers or []])),
        ]
        if memo:
            memo_signer = self.pubkey(signers[0]) if signers else auth
            ixs.append(create_memo(MemoParams(program_id=MEMO_PROGRAM_ID, signer=memo_signer,
                                              message=memo.encode()[:500])))
        return ixs

    def _submit(self, ixs: list, signer_names: list[str]) -> str:
        from solders.transaction import Transaction

        for n in signer_names:
            if n not in self.keys.names():
                raise ValueError(f"no keypair for {n}: cosign can only sign for its own wallets")
        payer = self.keys.keypair(self.fee_payer)
        signers = [payer]
        for n in signer_names:
            kp = self.keys.keypair(n)
            if kp.pubkey() not in [k.pubkey() for k in signers]:
                signers.append(kp)
        msg = self._message(ixs)
        tx = Transaction(signers, msg, msg.recent_blockhash)
        sig = self.rpc("sendTransaction", [base64.b64encode(bytes(tx)).decode(),
                                           {"encoding": "base64", "preflightCommitment": "confirmed"}])
        self._confirm(sig)
        return sig

    def _message(self, ixs: list):
        """A message under a fresh blockhash. Identical instructions under the same blockhash make an
        identical transaction, which the cluster drops as a duplicate (e.g. the same purchase twice in
        a row), so wait for a new blockhash if needed."""
        from solders.hash import Hash
        from solders.message import Message
        payer = self.pubkey(self.fee_payer)
        deadline = time.monotonic() + self.confirm_timeout
        while True:
            blockhash = Hash.from_string(
                self.rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
            msg = Message.new_with_blockhash(ixs, payer, blockhash)
            if bytes(msg) not in self.sent_messages:
                break
            if time.monotonic() > deadline:
                raise RpcError("no fresh blockhash for a repeated transaction")
            time.sleep(max(self.poll, 0.4))
        self.sent_messages.add(bytes(msg))
        return msg

    def _confirm(self, sig: str) -> None:
        deadline = time.monotonic() + self.confirm_timeout
        while True:
            st = self.rpc("getSignatureStatuses", [[sig]])["value"][0]
            if st and st.get("err") is not None:
                raise RpcError(f"transaction {sig} failed: {st['err']}")
            if st and st.get("confirmationStatus") in ("confirmed", "finalized"):
                return
            if time.monotonic() > deadline:
                raise RpcError(f"transaction {sig} not confirmed after {self.confirm_timeout:g}s")
            time.sleep(self.poll)
