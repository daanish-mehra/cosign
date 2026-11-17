#!/usr/bin/env python3
"""Print each USDC outflow from the agent wallet as a JSON line, live.

    export QUICKNODE_WSS_URL=wss://<your-endpoint>.solana-devnet.quiknode.pro/<token>/
    python scripts/watch_outflows.py [--address <pubkey>]

QUICKNODE_HTTP_URL is optional (defaults to the same URL over https). See cosign/watch.py.
"""

from cosign.watch import main

if __name__ == "__main__":
    raise SystemExit(main())
