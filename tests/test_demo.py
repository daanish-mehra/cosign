"""cosign demo end to end against a fake devnet + fake websocket. No network, no browser."""

import asyncio
import json
import os
import queue
import threading

import pytest

pytest.importorskip("solders")

from test_solana_ledger import FakeDevnet  # noqa: E402

from cosign import cli  # noqa: E402
from cosign.attacks import ATTACKER  # noqa: E402
from cosign.demo import AGENT, latest_results, logged_signatures, run_demo, scaled_amounts  # noqa: E402
from cosign.solana_ledger import KeyStore, SolanaLedger  # noqa: E402
from cosign.watch import watch  # noqa: E402


class StreamingDevnet(FakeDevnet):
    """Pushes each landed signature to listeners, like a logsSubscribe stream."""

    def __init__(self):
        super().__init__()
        self.listeners: list[queue.Queue] = []

    def sendTransaction(self, b64, opts):
        sig = super().sendTransaction(b64, opts)
        for q in self.listeners:
            q.put(sig)
        return sig


class FakeStream:
    def __init__(self, q, stop):
        self.q, self.stop = q, stop

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def send(self, _m):
        pass

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        yield json.dumps({"jsonrpc": "2.0", "id": 1, "result": 1})
        while not self.stop.is_set():
            try:
                sig = self.q.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.005)
                continue
            yield json.dumps({"method": "logsNotification",
                              "params": {"result": {"value": {"signature": sig, "err": None}}}})


class ThreadWatcher:
    """The real watch() coroutine, on a thread, fed by the fake devnet."""

    def __init__(self, net, agent, deliver=True):
        self.net, self.agent, self.deliver = net, agent, deliver
        self.started = self.stopped = False

    def start(self, log):
        self.started, self.stop_evt, q = True, threading.Event(), queue.Queue()
        if self.deliver:
            self.net.listeners.append(q)
        f = open(log, "w")
        self._f = f

        def emit(o):
            f.write(json.dumps(o) + "\n"); f.flush()

        def subscribed():
            f.write("subscribed\n"); f.flush()

        async def fetch(sig):
            return self.net.txs.get(sig)

        self.t = threading.Thread(target=lambda: asyncio.run(watch(
            "wss://fake", self.agent, fetch, connect=lambda u: FakeStream(q, self.stop_evt),
            emit=emit, on_subscribed=subscribed, reconnect=False)))
        self.t.start()

    def alive(self):
        return self.t.is_alive()

    def stop(self):
        self.stop_evt.set(); self.t.join(5); self._f.close()
        self.stopped = True


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COSIGN_KEYPAIRS", str(tmp_path / "keys.json"))
    opened = []
    monkeypatch.setattr("webbrowser.open", opened.append)
    net = StreamingDevnet()
    ledger = SolanaLedger(net, KeyStore(), poll=0)
    net.lamports[str(ledger.pubkey(AGENT))] = 5 * 10 ** 9
    net.mint_to(ledger, "operator", 19.4)
    (tmp_path / "results.json").write_text("[]")
    (tmp_path / "results-llama.json").write_text(json.dumps([{"agent": "x", "guards": ["none"], "limit": 0}]))
    os.utime(tmp_path / "results.json")              # newest but empty: must be skipped
    return net, ledger, opened, tmp_path


def demo(ledger, watcher, **kw):
    lines = []
    code = run_demo(ledger, watcher, treasury="operator", timeout=5, poll=0.01, out=lines.append, **kw)
    return code, "\n".join(lines)


def test_demo_tops_up_attacks_twice_logs_outflows_and_opens_report(world):
    net, ledger, opened, tmp = world
    w = ThreadWatcher(net, str(ledger.pubkey(AGENT)))
    code, out = demo(ledger, w)

    assert code == 0, out
    assert "topped up 10 USDC from operator" in out
    assert "attack asks for 2.5, purchase is 1" in out
    assert ledger.balance(ATTACKER) == 2.5                                  # unguarded run: money moved
    assert "--guards none: attacker got 2.5" in out and "--guards recommended: attacker got 0" in out
    assert "recipient not on allowlist" in out
    assert out.count("explorer.solana.com/tx/") == 4                       # top-up + 3 outflows
    assert "watch log confirmed all 3 outflows" in out and w.stopped

    logged = [json.loads(l) for l in (tmp / "logs/watch.log").read_text().splitlines() if l.startswith("{")]
    assert sorted(t["amount"] for t in logged) == [1.0, 1.0, 2.5]          # inflow (top-up) not logged
    html = (tmp / "cosign-report.html").read_text()
    assert logged[0]["signature"] in html and '"agent": "x"' in html       # results-llama.json + onchain
    assert opened and opened[0].endswith("cosign-report.html")


def test_demo_skips_top_up_when_funded_and_scales_amounts(world):
    net, ledger, _, _ = world
    net.mint_to(ledger, AGENT, 20)
    code, out = demo(ledger, ThreadWatcher(net, str(ledger.pubkey(AGENT))), open_page=False)
    assert code == 0 and "topped up" not in out
    assert "attack asks for 5, purchase is 2" in out and ledger.balance(ATTACKER) == 5


def test_demo_refuses_without_treasury_funds_or_sol(world):
    net, ledger, _, _ = world
    w = ThreadWatcher(net, str(ledger.pubkey(AGENT)))
    with pytest.raises(SystemExit, match="--treasury"):
        run_demo(ledger, w, treasury="treasury", out=lambda s: None)
    net.lamports.clear()
    with pytest.raises(SystemExit, match="SOL"):
        run_demo(ledger, w, treasury="operator", out=lambda s: None)
    assert not w.started and net.sent == 0


def test_demo_fails_if_outflows_never_reach_the_log(world):
    net, ledger, _, _ = world
    w = ThreadWatcher(net, str(ledger.pubkey(AGENT)), deliver=False)
    code, out = run_demo(ledger, w, treasury="operator", timeout=0.3, poll=0.01, open_page=False,
                         out=lambda s: None), None
    assert code == 1 and w.stopped


def test_helpers(tmp_path):
    assert scaled_amounts(20) == (5, 2) and scaled_amounts(10) == (2.5, 1) and scaled_amounts(400) == (5, 2)
    assert latest_results(tmp_path) is None
    (tmp_path / "results-a.json").write_text('[{"x": 1}]')
    (tmp_path / "results-b.json").write_text("[]")
    assert latest_results(tmp_path).name == "results-a.json"
    log = tmp_path / "w.log"
    log.write_text('watching x\nsubscribed\n{"signature": "s1", "amount": 1}\nnot json {\n')
    assert logged_signatures(log) == {"s1"}


def test_cli_demo_requires_websocket_url(monkeypatch):
    monkeypatch.delenv("QUICKNODE_WSS_URL", raising=False)
    with pytest.raises(SystemExit, match="QUICKNODE_WSS_URL"):
        cli.main(["demo"])
