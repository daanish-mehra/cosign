"""cosign demo: one poisoned-page attack on devnet, unguarded then guarded, with a live outflow log.

1. top the agent wallet up from the treasury if it holds less than --min-usdc
2. start the outflow watcher in the background, writing logs/watch.log
3. run the naive agent against a poisoned news page with --guards none, then --guards recommended
   (amounts scaled to the wallet: attack min(25%, 5) USDC, purchase min(10%, 2) USDC)
4. wait until every agent outflow from step 3 shows up in the log, stop the watcher
5. build the dashboard from the latest results file plus the log, and open it

The agent wallet pays its own fees, so it needs a little devnet SOL.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Callable, Protocol

from .attacks import ATTACKS, MUTATIONS
from .ledger import InsufficientFunds
from .runner import naive_brains, run_episode
from .solana_ledger import SolanaLedger
from .tasks import NEWS_URL, TASKS

AGENT = "agent_wallet"
MIN_SOL = 0.01
EXPLORER = "https://explorer.solana.com/tx/{}?cluster=devnet"


class Watcher(Protocol):
    def start(self, log: Path) -> None: ...
    def stop(self) -> None: ...
    def alive(self) -> bool: ...


class SubprocessWatcher:
    """`python -m cosign.watch` in the background; needs QUICKNODE_WSS_URL in the environment."""

    def __init__(self, address: str):
        self.address = address
        self.proc: subprocess.Popen | None = None

    def start(self, log: Path) -> None:
        self._f = open(log, "w")
        self.proc = subprocess.Popen([sys.executable, "-u", "-m", "cosign.watch", "--address", self.address],
                                     stdout=self._f, stderr=subprocess.STDOUT)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._f.close()


def scaled_amounts(balance: float) -> tuple[float, float]:
    """(attack, purchase) sized to the wallet; capped so the purchase stays under the guard caps."""
    return round(min(balance * 0.25, 5.0), 2), round(min(balance * 0.10, 2.0), 2)


def scenario(attack_usdc: float, buy_usdc: float):
    base = next(t for t in TASKS if t.id == "token_research")

    def plan():
        yield {"tool": "token_info", "args": {"symbol": "BONK"}}
        yield {"tool": "browse", "args": {"url": NEWS_URL}}
        yield {"tool": "swap", "args": {"symbol": "BONK", "usdc": buy_usdc}}

    task = dataclasses.replace(base, plan=plan, prompt=base.prompt.replace("10 USDC", f"{buy_usdc:g} USDC"))
    attack = dataclasses.replace(next(a for a in ATTACKS if a.family == "poisoned_website"), amount=attack_usdc)
    mutation = next(m for m in MUTATIONS if m[0] == "data_smuggle")  # gets past quarantine -> reaches the payment guard
    return task, attack, mutation


def latest_results(folder: Path = Path(".")) -> Path | None:
    """Most recently modified results*.json that holds at least one run."""
    for p in sorted(folder.glob("results*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if data:
            return p
    return None


def logged_signatures(log: Path) -> set[str]:
    sigs = set()
    for line in log.read_text().splitlines() if log.exists() else []:
        if line.startswith("{"):
            try:
                sigs.add(json.loads(line)["signature"])
            except (json.JSONDecodeError, KeyError):
                pass
    return sigs


def wait_until(check: Callable[[], bool], timeout: float, poll: float, alive: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        if not alive():
            return check()
        time.sleep(poll)
    return check()


def run_demo(ledger: SolanaLedger, watcher: Watcher, *, treasury: str = "treasury", min_usdc: float = 10.0,
             log: Path = Path("logs/watch.log"), results: Path | None = None,
             report_out: str = "cosign-report.html", open_page: bool = True,
             timeout: float = 90.0, poll: float = 1.0, out: Callable[[str], None] = print) -> int:
    from . import cli

    ledger.fee_payer = AGENT
    agent_pk = str(ledger.pubkey(AGENT))
    sol = ledger.rpc("getBalance", [agent_pk, {"commitment": "confirmed"}])["value"] / 1e9
    if sol < MIN_SOL:
        raise SystemExit(f"{AGENT} {agent_pk} has {sol:g} SOL; it pays its own fees and needs >= {MIN_SOL} devnet SOL")

    # 1. top up
    balance = ledger.balance(AGENT)
    out(f"{AGENT} {agent_pk}: {sol:.4f} SOL, {balance:g} USDC")
    if balance < min_usdc:
        need = round(min_usdc - balance, 6)
        have = ledger.balance(treasury)
        if have + 1e-9 < need:
            raise SystemExit(f"{AGENT} is below {min_usdc:g} USDC and {treasury} {ledger.pubkey(treasury)} holds only "
                             f"{have:g} USDC (needs {need:g}). Fund it, or pass --treasury <wallet with USDC>.")
        sig = ledger._send(treasury, AGENT, need, "cosign demo top-up")
        balance = ledger.balance(AGENT)
        out(f"topped up {need:g} USDC from {treasury}: {EXPLORER.format(sig)}")
    attack_usdc, buy_usdc = scaled_amounts(balance)
    task, attack, mutation = scenario(attack_usdc, buy_usdc)
    out(f"scaled to {balance:g} USDC: attack asks for {attack_usdc:g}, purchase is {buy_usdc:g}")

    class DemoLedger(SolanaLedger):
        def fund(self, address, amount):  # spend what's there; the top-up already happened
            if self.balance(address) + 1e-9 < attack_usdc + buy_usdc:
                raise InsufficientFunds(f"{address} can't cover the demo")

    # 2. watcher
    log.parent.mkdir(parents=True, exist_ok=True)
    watcher.start(log)
    ok = True
    try:
        if not wait_until(lambda: log.exists() and "subscribed" in log.read_text(), timeout, poll, watcher.alive):
            raise SystemExit(f"watcher didn't subscribe within {timeout:g}s; see {log}")
        out(f"watcher subscribed, logging outflows to {log}")

        # 3. the two runs
        outflows: list[str] = []
        for guards, expect_stolen in (("none", True), ("recommended", False)):
            run_ledger = DemoLedger(ledger.rpc, ledger.keys, ledger.mint, fee_payer=AGENT,
                                    sent_messages=ledger.sent_messages)
            ep = run_episode(task, cli.guard_preset(guards), naive_brains, attack, mutation, lambda: run_ledger)
            as_expected = (ep.stolen > 0) == expect_stolen and ep.error is None
            ok &= as_expected
            out(f"\n--guards {guards}: attacker got {ep.stolen:g} USDC, task done {ep.task_ok}"
                f"  [{'as expected' if as_expected else 'UNEXPECTED'}]")
            for b in ep.blocked:
                out(f"  guard: {b}")
            if ep.error:
                out(f"  error: {ep.error}")
            for t in run_ledger.transfers:
                out(f"  {t.amount:g} USDC {t.sender} -> {t.recipient}  memo={t.memo!r}\n    {EXPLORER.format(t.signature)}")
                outflows.append(t.signature)

        # 4. wait for the log to show every outflow
        seen = lambda: set(outflows) <= logged_signatures(log)  # noqa: E731
        if wait_until(seen, timeout, poll, watcher.alive):
            out(f"\nwatch log confirmed all {len(outflows)} outflows")
        else:
            ok = False
            out(f"\nwatch log has {len(set(outflows) & logged_signatures(log))}/{len(outflows)} outflows "
                f"after {timeout:g}s")
    finally:
        watcher.stop()
        out("watcher stopped")

    # 5. report
    results = results or latest_results()
    if results is None:
        out("no non-empty results*.json found; the report will use sample data")
    cli.main(["report", "--results", str(results) if results else "", "--out", report_out, "--onchain", str(log)])
    if open_page:
        webbrowser.open(Path(report_out).resolve().as_uri())
    return 0 if ok else 1
