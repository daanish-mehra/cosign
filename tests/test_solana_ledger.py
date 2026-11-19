"""SolanaLedger and the outflow watcher against a fake devnet. No network.

FakeDevnet decodes the real signed transactions SolanaLedger builds, checks signatures, and
applies the SPL transfers, so instruction layout, signers and ATA handling are all exercised.
"""

import asyncio
import base64
import json
import os
import stat

import pytest

pytest.importorskip("solders")
pytest.importorskip("spl")

from solders.hash import Hash  # noqa: E402
from solders.pubkey import Pubkey  # noqa: E402
from solders.transaction import Transaction  # noqa: E402
from spl.memo.constants import MEMO_PROGRAM_ID  # noqa: E402
from spl.token.constants import ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID  # noqa: E402

from cosign import cli  # noqa: E402
from cosign.attacks import ATTACKER  # noqa: E402
from cosign.ledger import InsufficientFunds  # noqa: E402
from cosign.runner import crash_test  # noqa: E402
from cosign.scoring import rate  # noqa: E402
from cosign.solana_ledger import (DEVNET_GENESIS, DEVNET_USDC, TREASURY, KeyStore,  # noqa: E402
                                  RpcError, SolanaLedger, parse_usdc_transfers)
from cosign.watch import watch  # noqa: E402

U = 10 ** 6
SYSTEM_PROGRAM = "11111111111111111111111111111111"


class FakeDevnet:
    def __init__(self, genesis=DEVNET_GENESIS):
        self.genesis = genesis
        self.tokens: dict[str, int] = {}      # token account -> units
        self.owner: dict[str, str] = {}       # token account -> owner
        self.lamports: dict[str, int] = {}
        self.txs: dict[str, dict] = {}        # signature -> jsonParsed tx
        self.delegate: dict[str, tuple[str, int]] = {}   # token account -> (delegate, units left)
        self.multisig: dict[str, tuple[int, list[str]]] = {}   # multisig account -> (m, signers)
        self.created: dict[str, tuple[int, str]] = {}         # system-created account -> (space, program owner)
        self.sent = 0

    def mint_to(self, ledger, name, usdc):
        ata = str(ledger.token_account(name))
        self.owner[ata] = str(ledger.pubkey(name))
        self.tokens[ata] = self.tokens.get(ata, 0) + int(usdc * U)

    def __call__(self, method, params):
        return getattr(self, method)(*params)

    def getGenesisHash(self):
        return self.genesis

    def getBalance(self, pk, _opts):
        return {"value": self.lamports.get(pk, 0)}

    def getLatestBlockhash(self, _opts):
        return {"value": {"blockhash": str(Hash.new_unique())}}   # a new blockhash each call, like a live cluster

    def getTokenAccountsByOwner(self, owner, flt, _opts):
        assert flt == {"mint": DEVNET_USDC}
        return {"value": [{"account": {"data": {"parsed": {"info": {"tokenAmount": {
            "uiAmountString": str(units / U)}}}}}} for a, units in self.tokens.items() if self.owner.get(a) == owner]}

    def getMinimumBalanceForRentExemption(self, space):
        return 6960 * (128 + space)

    def getAccountInfo(self, acct, _opts):
        if acct in self.multisig:
            m, signers = self.multisig[acct]
            return {"value": {"data": {"parsed": {"type": "multisig", "info": {
                "isInitialized": True, "numRequiredSigners": m, "numValidSigners": len(signers),
                "signers": signers}}}}}
        if acct not in self.tokens:
            return {"value": None}
        info = {"owner": self.owner[acct], "mint": DEVNET_USDC,
                "tokenAmount": {"uiAmountString": str(self.tokens[acct] / U)}}
        if acct in self.delegate:
            d, units = self.delegate[acct]
            info |= {"delegate": d, "delegatedAmount": {"uiAmountString": str(units / U)}}
        return {"value": {"data": {"parsed": {"info": info}}}}

    def getSignatureStatuses(self, sigs):
        return {"value": [{"confirmationStatus": "confirmed", "err": None} for _ in sigs]}

    def getSignaturesForAddress(self, acct, _opts):
        return [{"signature": s, "err": None} for s, tx in reversed(self.txs.items())
                if acct in [k["pubkey"] for k in tx["transaction"]["message"]["accountKeys"]]]

    def getTransaction(self, sig, _opts):
        return self.txs.get(sig)

    def sendTransaction(self, b64, _opts):
        tx = Transaction.from_bytes(base64.b64decode(b64))
        tx.verify()
        snapshot = (dict(self.tokens), dict(self.owner), dict(self.delegate), dict(self.multisig), dict(self.created))
        try:
            return self._apply(tx)
        except RpcError:          # preflight failure: nothing lands
            self.tokens, self.owner, self.delegate, self.multisig, self.created = snapshot
            raise

    def _apply(self, tx):                                       # every required signature is valid
        msg = tx.message
        keys = [str(k) for k in msg.account_keys]
        parsed, pre = [], dict(self.tokens)
        for ix in msg.instructions:
            prog = keys[ix.program_id_index]
            acc = [keys[i] for i in ix.accounts]
            data = bytes(ix.data)
            if prog == SYSTEM_PROGRAM:
                assert int.from_bytes(data[:4], "little") == 0, "expected CreateAccount"
                assert msg.is_signer(ix.accounts[0]) and msg.is_signer(ix.accounts[1])
                if acc[1] in self.created:
                    raise RpcError("account already in use")
                space = int.from_bytes(data[12:20], "little")
                self.created[acc[1]] = (space, str(Pubkey.from_bytes(data[20:52])))
            elif prog == str(ASSOCIATED_TOKEN_PROGRAM_ID):
                self.owner.setdefault(acc[1], acc[2])
                self.tokens.setdefault(acc[1], 0)
            elif prog == str(TOKEN_PROGRAM_ID):
                signer = lambda pos: msg.is_signer(ix.accounts[pos])  # noqa: E731
                if data[0] == 13:                                       # ApproveChecked
                    src, mint, dlg, owner = acc
                    assert signer(3) and self.owner[src] == owner and mint == DEVNET_USDC
                    self.delegate[src] = (dlg, int.from_bytes(data[1:9], "little"))
                    continue
                if data[0] == 5:                                        # Revoke
                    src, owner = acc
                    assert signer(1) and self.owner[src] == owner
                    self.delegate.pop(src, None)
                    continue
                if data[0] == 2:                                        # InitializeMultisig
                    ms, _rent, *signers = acc
                    assert self.created.get(ms) == (355, str(TOKEN_PROGRAM_ID)) and ms not in self.multisig
                    self.multisig[ms] = (data[1], signers)
                    continue
                assert data[0] == 12, "expected TransferChecked"
                src, mint, dst, auth = acc[:4]
                assert mint == DEVNET_USDC and data[9] == 6
                if auth in self.multisig:                               # m of the multisig's signers must sign
                    m, allowed = self.multisig[auth]
                    signed = {acc[i] for i in range(4, len(acc)) if signer(i) and acc[i] in allowed}
                    if len(signed) < m:
                        raise RpcError("custom program error: 0x8 (not enough multisig signers)")
                else:
                    assert signer(3)
                units = int.from_bytes(data[1:9], "little")
                if self.owner[src] != auth:                             # spending as a delegate
                    d, left = self.delegate.get(src, (None, 0))
                    if d != auth:
                        raise RpcError("custom program error: 0x4 (owner does not match)")
                    if units > left:
                        raise RpcError("custom program error: 0x1 (insufficient funds)")
                    self.delegate[src] = (d, left - units)
                    if left == units:
                        del self.delegate[src]
                if self.tokens[src] < units:
                    raise RpcError("custom program error: 0x1 (insufficient funds)")
                self.tokens[src] -= units
                self.tokens[dst] += units
                parsed.append({"program": "spl-token", "parsed": {"type": "transferChecked", "info": {
                    "source": src, "destination": dst, "authority": auth, "mint": mint,
                    "tokenAmount": {"amount": str(units), "decimals": 6, "uiAmountString": str(units / U)}}}})
            elif prog == str(MEMO_PROGRAM_ID):
                parsed.append({"program": "spl-memo", "parsed": data.decode()})
        sig = str(tx.signatures[0])
        bal = lambda b: [{"accountIndex": keys.index(a), "mint": DEVNET_USDC, "owner": self.owner[a]}  # noqa: E731
                         for a in b if a in keys]
        self.txs[sig] = {"slot": len(self.txs) + 1, "blockTime": 1_700_000_000,
                         "transaction": {"signatures": [sig], "message": {
                             "accountKeys": [{"pubkey": k} for k in keys], "instructions": parsed}},
                         "meta": {"err": None, "preTokenBalances": bal(pre), "postTokenBalances": bal(self.tokens)}}
        self.sent += 1
        return sig


@pytest.fixture
def devnet(tmp_path):
    net = FakeDevnet()
    ledger = SolanaLedger(net, KeyStore(tmp_path / "keys.json"), poll=0)
    net.lamports[str(ledger.pubkey(TREASURY))] = 10 ** 9
    net.mint_to(ledger, TREASURY, 10_000)
    return net, ledger


def test_transfer_balance_and_history_on_chain(devnet):
    net, ledger = devnet
    net.mint_to(ledger, "agent_wallet", 100)
    t = ledger.transfer("agent_wallet", ATTACKER, 12.5, "as instructed")

    assert t.signature in net.txs and ledger.transfers == [t]
    assert ledger.balance("agent_wallet") == 87.5 and ledger.balance(ATTACKER) == 12.5
    [h] = ledger.history("agent_wallet")
    assert (h.sender, h.recipient, h.amount, h.memo, h.signature) == \
        ("agent_wallet", ATTACKER, 12.5, "as instructed", t.signature)


def test_insufficient_funds_sends_nothing(devnet):
    net, ledger = devnet
    net.mint_to(ledger, "agent_wallet", 5)
    with pytest.raises(InsufficientFunds):
        ledger.transfer("agent_wallet", "dex_pool", 6)
    with pytest.raises(ValueError):
        ledger.transfer("agent_wallet", "dex_pool", 0)
    assert net.sent == 0


def test_fund_tops_up_from_treasury_and_sweep_returns_it(devnet):
    net, ledger = devnet
    net.mint_to(ledger, "agent_wallet", 30)
    ledger.fund("agent_wallet", 100)
    assert ledger.balance("agent_wallet") == 100 and ledger.transfers == []   # not an agent transfer
    ledger.fund("agent_wallet", 100)
    assert net.sent == 1                                                        # already topped up
    ledger.transfer("agent_wallet", ATTACKER, 40)
    assert ledger.sweep() == 100
    assert ledger.balance(TREASURY) == 10_030 and ledger.balance(ATTACKER) == 0


def test_fund_explains_what_the_treasury_is_missing(devnet):
    net, ledger = devnet
    net.lamports.clear()
    with pytest.raises(InsufficientFunds, match="airdrop"):
        ledger.fund("agent_wallet", 100)
    net.lamports[str(ledger.pubkey(TREASURY))] = 10 ** 9
    with pytest.raises(InsufficientFunds, match="faucet.circle.com"):
        ledger.fund("agent_wallet", 20_000)


def test_keypairs_persist_in_a_private_file(tmp_path):
    path = tmp_path / "cfg" / "keys.json"
    a = KeyStore(path).keypair("agent_wallet").pubkey()
    assert KeyStore(path).keypair("agent_wallet").pubkey() == a
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_refuses_anything_but_devnet(tmp_path):
    ledger = SolanaLedger(FakeDevnet(genesis="5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"), KeyStore(tmp_path / "k"))
    with pytest.raises(RuntimeError, match="not Solana devnet"):
        ledger.check_devnet()


def test_crash_test_runs_on_the_devnet_ledger(devnet):
    net, ledger = devnet
    cfg = cli.guard_preset("none")
    run = crash_test(cfg, max_mutations=1, ledgers=lambda: SolanaLedger(net, ledger.keys, poll=0))
    r = rate(run, cfg)
    assert r.p_compromise == 1.0 and r.benign_utility == 1.0
    assert all(e.error is None for e in run.episodes + run.benign)
    from cosign.attacks import LOOKALIKE
    paid_out = [p for p in run.pairs if p.attack not in ("approval_drain", "address_poisoning")]
    assert ledger.balance(ATTACKER) == 50 * len(paid_out)         # allowances are judged, not sent
    assert ledger.balance(LOOKALIKE) == 50 + 5                     # memo order + the misdirected fee


def test_cli_ledger_flag(devnet, monkeypatch, capsys):
    net, ledger = devnet
    monkeypatch.setattr("cosign.solana_ledger.SolanaLedger.from_env", classmethod(lambda cls: ledger))
    assert cli.main(["test", "--guards", "recommended", "--ledger", "devnet", "--max-mutations", "1", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["p_compromise"] == 0.0
    assert ledger.balance(ATTACKER) == 0 and ledger.balance("agent_wallet") == 0   # swept after the run
    with pytest.raises(SystemExit):
        cli.main(["test", "--ledger", "mainnet"])


# --- watcher -----------------------------------------------------------------
class FakeSocket:
    def __init__(self, frames):
        self.frames, self.sent = frames, []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def send(self, m):
        self.sent.append(json.loads(m))

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        for f in self.frames:
            yield json.dumps(f)


def note(sig, err=None):
    return {"method": "logsNotification", "params": {"result": {"value": {"signature": sig, "err": err, "logs": []}}}}


def test_watcher_prints_only_agent_outflows(devnet):
    net, ledger = devnet
    net.mint_to(ledger, "agent_wallet", 100)
    out_sig = ledger.transfer("agent_wallet", ATTACKER, 50, "as instructed").signature
    in_sig = ledger.transfer(TREASURY, "agent_wallet", 1).signature                # inflow: ignored
    agent = str(ledger.pubkey("agent_wallet"))
    sock = FakeSocket([{"jsonrpc": "2.0", "id": 1, "result": 7},
                       note(out_sig), note(in_sig), note(out_sig), note("failed", err={"x": 1})])
    fetched, emitted = [], []

    async def fetch(sig):
        fetched.append(sig)
        return net.txs.get(sig)

    asyncio.run(watch("wss://fake", agent, fetch, connect=lambda url: sock, emit=emitted.append, reconnect=False))

    assert sock.sent[0]["method"] == "logsSubscribe" and sock.sent[0]["params"][0] == {"mentions": [agent]}
    assert fetched == [out_sig, in_sig]                                            # deduped, failed tx skipped
    assert [(e["from"], e["to"], e["amount"], e["memo"]) for e in emitted] == \
        [(agent, str(ledger.pubkey(ATTACKER)), 50.0, "as instructed")]


def test_parse_ignores_failed_and_other_mints():
    assert parse_usdc_transfers(None) == []
    assert parse_usdc_transfers({"meta": {"err": {"x": 1}}, "transaction": {}}) == []
    tx = {"transaction": {"signatures": ["s"], "message": {"accountKeys": [], "instructions": [
        {"program": "spl-token", "parsed": {"type": "transferChecked", "info": {
            "source": "a", "destination": "b", "mint": "OTHER", "tokenAmount": {"uiAmountString": "1"}}}}]}},
          "meta": {"err": None}}
    assert parse_usdc_transfers(tx) == []


# --- on-chain spend limit (SPL delegation) ----------------------------------------
from cosign.grant import effective_limit, scaled_tiers, to_usdc  # noqa: E402


def row(limit, trials=3, mutations="all", ua=1.0):
    from cosign.attacks import MUTATIONS
    mutations = len(MUTATIONS) if mutations == "all" else mutations
    return {"agent": "a", "guards": ["x"], "score": 90, "limit": limit, "trials": trials,
            "mutations": mutations, "utility_under_attack": ua}


def test_effective_limit_fails_closed_and_scales():
    assert effective_limit(row(5000)) == (5000, [])
    lim, notes = effective_limit(row(5000, mutations=None))        # strength not recorded
    assert lim == 250 and "weak test" in notes[0]
    assert effective_limit(row(5000, ua=0.5))[0] == 0
    assert to_usdc(5000) == 20 and to_usdc(250) == 1 and to_usdc(25) == 0.1
    assert scaled_tiers()[-1] == 20 and to_usdc(5000, max_usdc=5000) == 5000


@pytest.fixture
def vault(devnet):
    net, ledger = devnet
    ledger.fee_payer = TREASURY
    net.mint_to(ledger, "operator", 20)
    return net, ledger


def test_delegation_enforces_the_allowance_on_chain(vault):
    net, ledger = vault
    ledger.approve("operator", "agent_wallet", 1.0)
    v = ledger.vault("operator")
    assert v["delegate"] == str(ledger.pubkey("agent_wallet")) and v["delegated"] == 1.0

    ledger.spend_as_delegate("agent_wallet", "operator", "dex_pool", 0.6, "swap")
    assert ledger.vault("operator")["delegated"] == 0.4 and ledger.balance("dex_pool") == 0.6
    with pytest.raises(RpcError, match="insufficient"):                 # over the remaining allowance
        ledger.spend_as_delegate("agent_wallet", "operator", ATTACKER, 0.5)
    with pytest.raises(RpcError, match="owner does not match"):         # some other key
        ledger.spend_as_delegate("attacker_wallet", "operator", ATTACKER, 0.1)
    assert ledger.balance(ATTACKER) == 0 and ledger.vault("operator")["balance"] == 19.4

    ledger.approve("operator", "agent_wallet", 2.0)                     # re-approve replaces it
    assert ledger.vault("operator")["delegated"] == 2.0
    ledger.revoke("operator")
    assert ledger.vault("operator")["delegate"] is None
    with pytest.raises(RpcError):
        ledger.spend_as_delegate("agent_wallet", "operator", "dex_pool", 0.1)


def test_cli_grant_approves_then_revokes(vault, tmp_path, monkeypatch, capsys):
    net, ledger = vault
    monkeypatch.setattr("cosign.solana_ledger.SolanaLedger.from_env", classmethod(lambda cls: ledger))
    results = tmp_path / "results.json"
    results.write_text(json.dumps([row(0, ua=0.25), row(5000), row(5000, mutations=None)]))

    cli.main(["grant", "--results", str(results), "--run", "1", "--fee-payer", TREASURY])
    assert ledger.vault("operator")["delegated"] == 20
    out = capsys.readouterr().out
    assert "approve" in out and "explorer.solana.com/tx/" in out and "cluster=devnet" in out

    cli.main(["grant", "--results", str(results), "--run", "2", "--fee-payer", TREASURY])
    assert ledger.vault("operator")["delegated"] == 1                   # capped: strength unrecorded
    assert "weak test" in capsys.readouterr().out

    cli.main(["grant", "--results", str(results), "--run", "0", "--fee-payer", TREASURY])
    assert ledger.vault("operator")["delegate"] is None and "revoke" in capsys.readouterr().out

    with pytest.raises(SystemExit, match="out of range"):
        cli.main(["grant", "--results", str(results), "--run", "3"])


# --- 2-of-2 multisig vault ------------------------------------------------------------
@pytest.fixture
def msvault(devnet):
    net, ledger = devnet
    ledger.fee_payer = TREASURY
    v = ledger.create_multisig_vault("agent_wallet", "cosigner")
    return net, ledger, v


def test_vault_create_makes_a_2_of_2_multisig_owning_a_usdc_account(msvault):
    net, ledger, v = msvault
    assert v["created"] and v["m"] == 2
    assert sorted(v["signers"]) == sorted([str(ledger.pubkey("agent_wallet")), str(ledger.pubkey("cosigner"))])
    assert net.owner[v["token_account"]] == v["multisig"] and v["balance"] == 0
    again = ledger.create_multisig_vault("agent_wallet", "cosigner")
    assert not again["created"] and again["multisig"] == v["multisig"]
    with pytest.raises(RuntimeError, match="other signers"):
        ledger.create_multisig_vault("agent_wallet", "someone_else")
    with pytest.raises(ValueError):
        ledger.create_multisig_vault("x", "x")


def test_vault_fund_tops_up_and_sweep_leaves_it(msvault):
    net, ledger, v = msvault
    assert ledger.fund_vault("agent_wallet", 12) == 12
    assert ledger.fund_vault("agent_wallet", 12) == 12            # already topped up
    assert ledger.sweep() == 0 and ledger.multisig_vault("agent_wallet")["balance"] == 12
    with pytest.raises(RuntimeError, match="vault create"):
        ledger.fund_vault("nobody", 1)


def test_vault_needs_both_signatures_on_chain(msvault):
    net, ledger, v = msvault
    ledger.fund_vault("agent_wallet", 10)
    ledger.fee_payer = "agent_wallet"
    net.lamports[str(ledger.pubkey("agent_wallet"))] = 10 ** 9
    name = ledger.multisig_name("agent_wallet")
    ixs = ledger._transfer_ixs(name, "dex_pool", 1, "", signers=["agent_wallet"])
    with pytest.raises(RpcError, match="not enough multisig signers"):    # agent alone
        ledger._submit(ixs, ["agent_wallet"])
    ixs = ledger._transfer_ixs(name, "dex_pool", 1, "", signers=["agent_wallet", "cosigner"])
    ledger._submit(ixs, ["agent_wallet", "cosigner"])
    assert ledger.balance(name) == 9 and ledger.balance("dex_pool") == 1


def test_cli_vault_create_and_fund_print_addresses_not_keys(devnet, monkeypatch, capsys):
    net, ledger = devnet
    monkeypatch.setattr("cosign.solana_ledger.SolanaLedger.from_env", classmethod(lambda cls: ledger))
    assert cli.main(["vault", "create", "--agent", "agent_wallet", "--cosigner", "cosigner"]) == 0
    out = capsys.readouterr().out
    v = ledger.multisig_vault("agent_wallet")
    assert v["multisig"] in out and v["token_account"] in out and str(ledger.pubkey("cosigner")) in out
    assert cli.main(["vault", "fund", "--agent", "agent_wallet", "--usdc", "7"]) == 0
    assert "holds 7 USDC" in capsys.readouterr().out
    from solders.keypair import Keypair
    secrets = json.loads(ledger.keys.path.read_text())
    printed = out + capsys.readouterr().out
    assert not any(str(Keypair.from_bytes(bytes(k))) in printed or str(k) in printed for k in secrets.values())


def test_http_rpc_retries_rate_limits(monkeypatch):
    import io
    import urllib.error
    import urllib.request
    from cosign.solana_ledger import http_rpc
    calls, sleeps = [], []

    def fake_urlopen(req, timeout):
        calls.append(req)
        if len(calls) < 3:
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)
        return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":42}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert http_rpc("http://rpc", sleep=sleeps.append)("getSlot", []) == 42
    assert len(calls) == 3 and sleeps == [0.5, 1.0]

    calls.clear()
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout: (_ for _ in ()).throw(urllib.error.HTTPError("u", 401, "no", {}, None)))
    try:
        http_rpc("http://rpc", sleep=sleeps.append)("getSlot", [])
        raise AssertionError("401 should not be retried")
    except urllib.error.HTTPError as e:
        assert e.code == 401
