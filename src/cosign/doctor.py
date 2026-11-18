"""`cosign doctor`: a pass/fail checklist of everything cosign needs, with the fix for each failure.

Checks env keys (presence only: values are never printed), the RPC and WSS endpoints, the devnet
keypairs, their SOL/USDC balances, and the guard. Read-only: it never creates keypairs, sends
transactions or prints secrets. URLs are shown as scheme://host only (QuickNode puts the token in
the path).
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .solana_ledger import DEFAULT_KEYPAIRS, DEVNET_GENESIS, DEVNET_RPC, DEVNET_USDC, TREASURY, http_rpc

AGENT = "agent_wallet"
MIN_SOL = 0.01          # demo.MIN_SOL: enough for fees
SOL_FAUCET = "https://faucet.solana.com"
USDC_FAUCET = "https://faucet.circle.com"

Rpc = Callable[[str, list], Any]


@dataclass
class Check:
    name: str
    ok: bool | None          # None = skipped / not applicable
    detail: str = ""
    fix: str = ""


def host_of(url: str) -> str:
    u = urlsplit(url)
    return f"{u.scheme}://{u.hostname}" if u.scheme and u.hostname else "(unparseable URL)"


# --- env -------------------------------------------------------------------------
def check_env(env: dict[str, str]) -> list[Check]:
    out = []
    llm = [k for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY") if env.get(k)]
    out.append(Check("LLM API key", bool(llm), f"set: {', '.join(llm)}" if llm else "none set",
                     "export ANTHROPIC_API_KEY=... or OPENAI_API_KEY=... (only LLM agents need one; "
                     "--agent naive runs without)"))
    out.append(Check("QUICKNODE_WSS_URL", bool(env.get("QUICKNODE_WSS_URL")),
                     "set" if env.get("QUICKNODE_WSS_URL") else "not set",
                     "export QUICKNODE_WSS_URL=wss://<your devnet endpoint> (needed by `cosign demo` and the watcher)"))
    for k, default in (("SOLANA_RPC_URL", f"default {DEVNET_RPC}"), ("COSIGN_KEYPAIRS", f"default {DEFAULT_KEYPAIRS}"),
                       ("COSIGN_USDC_MINT", "default Circle devnet USDC")):
        out.append(Check(k, None, "set" if env.get(k) else default))
    return out


# --- endpoints -------------------------------------------------------------------
def check_rpc(url: str, rpc: Rpc) -> Check:
    name = f"RPC {host_of(url)}"
    try:
        genesis = rpc("getGenesisHash", [])
    except Exception as e:
        return Check(name, False, f"unreachable ({type(e).__name__})",
                     "check SOLANA_RPC_URL and your network; unset it to use the public devnet RPC")
    if genesis != DEVNET_GENESIS:
        return Check(name, False, "reachable but not devnet",
                     "point SOLANA_RPC_URL at a Solana devnet endpoint (cosign refuses other clusters)")
    return Check(name, True, "reachable, devnet")


def ws_probe(url: str, timeout: float = 5.0) -> None:
    """Open and close a websocket (websockets package), else just a TCP/TLS connection."""
    try:
        from websockets.sync.client import connect
    except ImportError:
        u = urlsplit(url)
        port = u.port or (443 if u.scheme == "wss" else 80)
        with socket.create_connection((u.hostname, port), timeout=timeout) as s:
            if u.scheme == "wss":
                ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname).close()
        return
    with connect(url, open_timeout=timeout, close_timeout=timeout):
        pass


def check_wss(url: str | None, probe: Callable[[str], None]) -> Check:
    if not url:
        return Check("WSS endpoint", None, "skipped: QUICKNODE_WSS_URL not set")
    name = f"WSS {host_of(url)}"
    try:
        probe(url)
    except Exception as e:
        return Check(name, False, f"unreachable ({type(e).__name__})",
                     "check QUICKNODE_WSS_URL is your endpoint's wss:// URL and the endpoint is on devnet")
    return Check(name, True, "reachable")


# --- keypairs and balances --------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def read_keypairs(path: Path) -> dict[str, str]:
    """{name: public key} without creating anything. A Solana keypair is 32 secret bytes + 32 public."""
    raw = json.loads(path.read_text())
    return {name: b58encode(bytes(secret[32:64])) for name, secret in raw.items()}


def _short(path: Path) -> str:
    home = str(Path.home())
    return "~" + str(path)[len(home):] if str(path).startswith(home + os.sep) else str(path)


def check_keypairs(path: Path) -> tuple[list[Check], dict[str, str]]:
    fix_create = ("created on first devnet use: `cosign test --agent naive --guards recommended --ledger devnet`, "
                  "then fund it")
    if not path.exists():
        return [Check("keypair file", False, f"{_short(path)} missing", fix_create)], {}
    checks = []
    mode = path.stat().st_mode & 0o777
    checks.append(Check("keypair file", mode & 0o077 == 0, f"{_short(path)} (mode {mode:o})",
                        f"chmod 600 {_short(path)}"))
    try:
        keys = read_keypairs(path)
    except (ValueError, TypeError, KeyError) as e:
        return checks + [Check("keypairs readable", False, f"unreadable ({type(e).__name__})",
                               f"restore {path} from a backup, or move it aside to start fresh")], {}
    for name in (TREASURY, AGENT):
        checks.append(Check(f"keypair {name}", name in keys, keys.get(name, "missing"), fix_create))
    others = sorted(set(keys) - {TREASURY, AGENT})
    if others:
        checks.append(Check("other keypairs", None, ", ".join(others)))
    return checks, keys


def sol_balance(rpc: Rpc, pubkey: str) -> float:
    return rpc("getBalance", [pubkey, {"commitment": "confirmed"}])["value"] / 1e9


def usdc_balance(rpc: Rpc, pubkey: str, mint: str) -> float:
    res = rpc("getTokenAccountsByOwner", [pubkey, {"mint": mint}, {"encoding": "jsonParsed", "commitment": "confirmed"}])
    return sum(float(a["account"]["data"]["parsed"]["info"]["tokenAmount"]["uiAmountString"]) for a in res["value"])


def check_balances(keys: dict[str, str], rpc: Rpc, mint: str) -> list[Check]:
    out = []
    for name in (TREASURY, AGENT):
        if name not in keys:
            out.append(Check(f"{name} balances", None, "skipped: no keypair"))
            continue
        pk = keys[name]
        try:
            sol, usdc = sol_balance(rpc, pk), usdc_balance(rpc, pk, mint)
        except Exception as e:
            out.append(Check(f"{name} balances", False, f"RPC error ({type(e).__name__})", "fix the RPC check first"))
            continue
        out.append(Check(f"{name} SOL", sol >= MIN_SOL, f"{sol:g} SOL",
                         f"airdrop devnet SOL to {pk} at {SOL_FAUCET} (fees need >= {MIN_SOL})"))
        if name == TREASURY:
            out.append(Check(f"{name} USDC", usdc > 0, f"{usdc:g} USDC",
                             f"get devnet USDC for {pk} at {USDC_FAUCET}"))
        else:
            out.append(Check(f"{name} USDC", None, f"{usdc:g} USDC (the demo tops it up from the treasury)"))
    return out


# --- guard -----------------------------------------------------------------------
def check_guard_self_test() -> Check:
    """The recommended guards must block a payment to an attacker and allow a legit swap."""
    from .attacks import ATTACKER
    from .cli import guard_preset
    from .guard import Guard
    from .tasks import make_world
    try:
        env = make_world()
        g = Guard(env, guard_preset("recommended"))
        blocked = g.pay(ATTACKER, 50).text.startswith("blocked")
        allowed = g.swap("SOL", 5).text.startswith("swapped")
    except Exception as e:
        return Check("guard self-test", False, f"crashed ({type(e).__name__}: {e})",
                     "reinstall: pip install -e .  and run pytest")
    ok = blocked and allowed
    return Check("guard self-test", ok, "blocks attacker, allows legit swap" if ok else
                 f"attacker {'blocked' if blocked else 'NOT blocked'}, swap {'allowed' if allowed else 'blocked'}",
                 "the guard code is broken: run pytest")


def http_probe(url: str, timeout: float = 5.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def check_guard_url(url: str | None, probe: Callable[[str], int]) -> Check:
    if not url:
        return Check("guard service", None, "skipped: pass --guard-url to check a running guard")
    name = f"guard service {host_of(url)}"
    try:
        status = probe(url)
    except Exception as e:
        return Check(name, False, f"unreachable ({type(e).__name__})", "start the guard service, or fix --guard-url")
    return Check(name, status < 500, f"HTTP {status}", "the guard service is up but erroring: check its logs")


# --- run -------------------------------------------------------------------------
def run_checks(env: dict[str, str] | None = None,
               rpc_factory: Callable[[str], Rpc] = lambda url: http_rpc(url, timeout=10),
               ws: Callable[[str], None] = ws_probe, http: Callable[[str], int] = http_probe,
               guard_url: str | None = None) -> list[Check]:
    env = dict(os.environ) if env is None else env
    checks = check_env(env)
    rpc_url = env.get("SOLANA_RPC_URL") or DEVNET_RPC
    rpc = rpc_factory(rpc_url)
    rpc_check = check_rpc(rpc_url, rpc)
    checks += [rpc_check, check_wss(env.get("QUICKNODE_WSS_URL"), ws)]
    kp_checks, keys = check_keypairs(Path(env.get("COSIGN_KEYPAIRS") or DEFAULT_KEYPAIRS).expanduser())
    checks += kp_checks
    if rpc_check.ok:
        checks += check_balances(keys, rpc, env.get("COSIGN_USDC_MINT") or DEVNET_USDC)
    else:
        checks.append(Check("devnet balances", None, "skipped: RPC check failed"))
    checks += [check_guard_self_test(), check_guard_url(guard_url, http)]
    return checks


def render(checks: list[Check]) -> str:
    width = max(len(c.name) for c in checks)
    lines = ["cosign doctor", ""]
    for c in checks:
        mark = {True: "[pass]", False: "[FAIL]", None: "[ -- ]"}[c.ok]
        lines.append(f"  {mark} {c.name:<{width}}  {c.detail}".rstrip())
        if c.ok is False and c.fix:
            lines.append(f"         {'':<{width}}  fix: {c.fix}")
    p, f = sum(c.ok is True for c in checks), sum(c.ok is False for c in checks)
    lines += ["", f"{p} passed, {f} failed, {len(checks) - p - f} skipped"]
    return "\n".join(lines)


def main(guard_url: str | None = None) -> int:
    checks = run_checks(guard_url=guard_url)
    print(render(checks))
    return 1 if any(c.ok is False for c in checks) else 0
