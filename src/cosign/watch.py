"""Live feed of the agent wallet's USDC outflows over a Solana websocket (e.g. a QuickNode WSS endpoint).

Subscribes with logsSubscribe(mentions=[agent]) at "confirmed", fetches each new transaction over
HTTP (getTransaction, jsonParsed), and prints one JSON line per outflow:
    {"signature", "slot", "block_time", "from", "to", "amount", "memo"}
Reconnects with backoff if the socket drops. JSON lines are meant to be piped into the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Awaitable, Callable

from .solana_ledger import DEVNET_USDC, http_rpc, parse_usdc_transfers

FetchTx = Callable[[str], Awaitable[dict | None]]


def http_url_for(wss_url: str) -> str:
    return "https://" + wss_url.split("://", 1)[1] if wss_url.startswith("wss://") else \
        "http://" + wss_url.split("://", 1)[1]


def rpc_fetcher(http_url: str, retries: int = 5, delay: float = 1.0) -> FetchTx:
    rpc = http_rpc(http_url)

    async def fetch(sig: str) -> dict | None:
        for _ in range(retries):  # a confirmed tx can lag behind its log notification
            tx = await asyncio.to_thread(rpc, "getTransaction", [sig, {
                "encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0}])
            if tx:
                return tx
            await asyncio.sleep(delay)
        return None
    return fetch


async def watch(wss_url: str, agent: str, fetch_tx: FetchTx, *, mint: str = DEVNET_USDC,
                connect: Callable[[str], Any] | None = None, emit: Callable[[dict], None] | None = None,
                on_subscribed: Callable[[], None] | None = None,
                reconnect: bool = True, max_backoff: float = 30.0) -> None:
    if connect is None:
        import websockets
        connect = websockets.connect
    emit = emit or (lambda o: print(json.dumps(o), flush=True))
    on_subscribed = on_subscribed or (lambda: print("subscribed", file=sys.stderr, flush=True))
    seen: set[str] = set()
    backoff = 1.0
    while True:
        try:
            async with connect(wss_url) as ws:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "logsSubscribe",
                                          "params": [{"mentions": [agent]}, {"commitment": "confirmed"}]}))
                backoff = 1.0
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("id") == 1 and "result" in msg:
                        on_subscribed()   # outflows from here on are seen
                        continue
                    if msg.get("method") != "logsNotification":
                        continue  # subscription ack, pings
                    value = msg["params"]["result"]["value"]
                    sig = value["signature"]
                    if value.get("err") is not None or sig in seen:
                        continue
                    seen.add(sig)
                    for t in parse_usdc_transfers(await fetch_tx(sig), mint):
                        if t["from"] == agent and t["to"] != agent:
                            emit(t)
        except (OSError, ConnectionError) as e:
            if not reconnect:
                raise
            print(f"websocket dropped ({e}); reconnecting in {backoff:g}s", file=sys.stderr)
        else:
            if not reconnect:
                return
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, max_backoff)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--address", help="wallet to watch (default: agent_wallet from the cosign keypair file)")
    ap.add_argument("--mint", default=os.environ.get("COSIGN_USDC_MINT") or DEVNET_USDC)
    args = ap.parse_args(argv)

    wss = os.environ.get("QUICKNODE_WSS_URL")
    if not wss:
        print("set QUICKNODE_WSS_URL to your endpoint's wss:// URL", file=sys.stderr)
        return 2
    http = os.environ.get("QUICKNODE_HTTP_URL") or http_url_for(wss)
    address = args.address
    if not address:
        from .solana_ledger import KeyStore
        address = str(KeyStore().keypair("agent_wallet").pubkey())
    print(f"watching {address} for USDC outflows", file=sys.stderr)
    try:
        asyncio.run(watch(wss, address, rpc_fetcher(http), mint=args.mint))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
