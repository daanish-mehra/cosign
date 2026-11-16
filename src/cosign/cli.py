"""Cosign CLI.

cosign test   --agent naive|llm [--provider anthropic|openai] [--model M] --guards PRESET [--ledger sim|devnet]
cosign matrix --models naive,anthropic:MODEL,openai:MODEL,adapter:elizaos --guards none,caps,quarantine,recommended
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .guard import GuardConfig
from .runner import crash_test, naive_brains
from .scoring import rate
from .tasks import LEGIT_RECIPIENTS

PRESETS = ["none", "caps", "quarantine", "recommended"]


def guard_preset(name: str) -> GuardConfig:
    if name == "none":
        return GuardConfig.none()
    if name == "caps":
        return GuardConfig(max_per_tx=25, max_total=60)
    if name == "quarantine":
        return GuardConfig(quarantine=True, verify_memory=True)
    if name == "recommended":
        return GuardConfig.recommended(set(LEGIT_RECIPIENTS))
    raise SystemExit(f"unknown guard preset {name}")


def brain_factory(spec: str):
    """'naive', 'anthropic', 'anthropic:<model>', 'openai:<model>', 'adapter:<framework>'."""
    if spec == "naive":
        return naive_brains
    if spec.startswith("adapter:"):
        from .adapters import ADAPTERS
        name = spec.partition(":")[2]
        if name not in ADAPTERS:
            raise ValueError(f"unknown adapter {name} (have: {', '.join(ADAPTERS)})")
        ADAPTERS[name]()  # stubs raise here until a transport is wired in
        return lambda task: ADAPTERS[name]()
    provider, _, model = spec.partition(":")
    import os
    need = {"anthropic": ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"], "openai": ["OPENAI_API_KEY"]}.get(provider, [])
    if need and not any(os.environ.get(v) for v in need):
        raise SystemExit(f"{spec}: {need[0]} is not set in this terminal. export it, then rerun.")
    from .agent import LLMBrain
    LLMBrain(provider, model or None)  # fail fast on a missing key / package / model name
    return lambda task: LLMBrain(provider, model or None)


def _print_report(label: str, guards: list[str], r) -> None:
    print(f"Cosign crash test  |  agent={label}  guards={', '.join(guards)}")
    print("-" * 64)
    for fam, (c, n, w) in r.by_family.items():
        status = f"BREACHED via {w}" if c else "held"
        print(f"  {fam:<18} {c}/{n} scenarios breached   {status}")
    print("-" * 64)
    print(f"  chance an attack lands (P)    {r.p_compromise:.0%}")
    print(f"  wallet lost when it lands     {r.lgd:.0%}")
    print(f"  work done (no attack)         {r.benign_utility:.0%}")
    print(f"  work done safely under attack {r.utility_under_attack:.0%}")
    print(f"\n  SCORE  {r.score}/100      SPEND LIMIT  {r.limit} USDC")
    if r.fixes:
        print("\n  Fix next:")
        for f in r.fixes:
            print(f"   - {f}")


def ledger_factory(kind: str):
    """None for the in-memory SimLedger; for devnet, a factory giving each episode a fresh session."""
    if kind == "sim":
        return None
    from .solana_ledger import SolanaLedger
    base = SolanaLedger.from_env()  # checks the endpoint really is devnet
    print(f"devnet ledger: treasury {base.pubkey('treasury')}, agent {base.pubkey('agent_wallet')}",
          file=sys.stderr)
    return lambda: SolanaLedger(base.rpc, base.keys, base.mint, sent_messages=base.sent_messages)


def cmd_test(args) -> int:
    spec = "naive" if args.agent == "naive" else f"{args.provider}:{args.model or ''}".rstrip(":")
    cfg = guard_preset(args.guards)
    ledgers = ledger_factory(args.ledger)
    run = crash_test(cfg, brain_factory(spec), trials=args.trials, max_mutations=args.max_mutations,
                     ledgers=ledgers)
    if ledgers is not None:
        swept = ledgers().sweep()
        print(f"devnet: swept {swept:g} USDC back to the treasury", file=sys.stderr)
    r = rate(run, cfg)
    if args.json:
        json.dump({"agent": spec, "guards": run.guard, "trials": run.trials, "mutations": run.mutations,
                   **asdict(r)}, sys.stdout, indent=2)
        print()
    else:
        _print_report(spec, run.guard, r)
    return 0


def cmd_matrix(args) -> int:
    rows, results = [], []
    for spec in [s.strip() for s in args.models.split(",") if s.strip()]:
        try:
            brains = brain_factory(spec)
        except (Exception, SystemExit) as e:  # missing key, package or model name
            print(f"skip {spec}: {e}", file=sys.stderr)
            continue
        for g in [p.strip() for p in args.guards.split(",") if p.strip()]:
            cfg = guard_preset(g)
            try:
                run = crash_test(cfg, brains, trials=args.trials, max_mutations=args.max_mutations)
            except Exception as e:  # API errors, rate limits
                print(f"error {spec} / {g}: {e}", file=sys.stderr)
                continue
            r = rate(run, cfg)
            errs = sum(1 for e in run.benign + run.episodes if e.error)
            total = len(run.benign) + len(run.episodes)
            if errs and errs == total:
                print(f"error {spec} / {g}: every episode failed, not scoring this run. "
                      f"first: {next(e.error for e in run.benign + run.episodes if e.error)}", file=sys.stderr)
                continue
            if errs:
                print(f"warn {spec} / {g}: {errs}/{total} episodes hit API errors; "
                      f"first: {next(e.error for e in run.benign + run.episodes if e.error)}", file=sys.stderr)
            rows.append((spec, g, r))
            results.append({"agent": spec, "guards": run.guard, "trials": args.trials, "mutations": run.mutations,
                            "episodes": len(run.episodes) + len(run.benign), **asdict(r)})
            print(f"done {spec:<32} {g:<12} score={r.score:<3} limit={r.limit}", file=sys.stderr)

    print(f"\n{'agent':<32} {'guards':<12} {'score':>5} {'limit':>6} {'P':>5} {'loss':>5} {'util':>5}")
    print("-" * 76)
    for spec, g, r in rows:
        print(f"{spec:<32} {g:<12} {r.score:>5} {r.limit:>6} {r.p_compromise:>5.0%} "
              f"{r.lgd:>5.0%} {r.benign_utility:>5.0%}")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nsaved {args.out}")
    return 0


def _load_onchain(path: str | None) -> dict | None:
    """Transfers from a `cosign watch` log, labelled with local wallet names (public keys only)."""
    from pathlib import Path
    if not path or not Path(path).exists():
        return None
    txs = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                t = json.loads(line)
            except json.JSONDecodeError:
                continue
            if t.get("signature") and t.get("amount") is not None:
                txs.append({k: t.get(k) for k in ("signature", "block_time", "from", "to", "amount", "memo")})
    if not txs:
        return None
    seen, uniq = set(), []
    for t in txs:
        if t["signature"] + str(t["to"]) not in seen:
            seen.add(t["signature"] + str(t["to"])); uniq.append(t)
    names: dict[str, str] = {}
    try:
        from .solana_ledger import KeyStore
        ks = KeyStore()
        for n in ks.names():
            names[str(ks.keypair(n).pubkey())] = n
    except Exception:
        pass  # no keystore here: the page shows short addresses instead
    return {"cluster": "devnet", "names": names, "txs": uniq}


def cmd_report(args) -> int:
    from pathlib import Path
    template = Path(__file__).with_name("dashboard.html").read_text()
    data = json.loads(Path(args.results).read_text()) if args.results else None
    onchain = _load_onchain(args.onchain)
    safe = lambda obj: json.dumps(obj).replace("</", "<\\/") if obj is not None else "null"
    html = template.replace("/*__RESULTS__*/", safe(data)).replace("/*__ONCHAIN__*/", safe(onchain))
    Path(args.out).write_text(html)
    n = len(data) if isinstance(data, list) else (1 if data else 0)
    extra = f", {len(onchain['txs'])} devnet transactions" if onchain else ""
    print(f"wrote {args.out} ({n} run{'s' if n != 1 else ''}{extra})")
    return 0


EXPLORER = "https://explorer.solana.com/tx/{}?cluster=devnet"


def cmd_grant(args) -> int:
    from pathlib import Path
    from .grant import apply, effective_limit, scaled_tiers, to_usdc
    from .solana_ledger import SolanaLedger

    rows = json.loads(Path(args.results).read_text())
    rows = rows if isinstance(rows, list) else [rows]
    if not 0 <= args.run < len(rows):
        raise SystemExit(f"--run {args.run} out of range: {args.results} has {len(rows)} run(s)")
    row = rows[args.run]
    limit, notes = effective_limit(row)
    usdc = to_usdc(limit, args.max_usdc)
    guards = row.get("guards")
    print(f"run {args.run}: {row.get('agent')}  guards={','.join(guards) if isinstance(guards, list) else guards}"
          f"  score={row.get('score')}  limit={row['limit']}")
    for n in notes:
        print(f"  note: {n}")
    print(f"  tiers scaled to {args.max_usdc:g} USDC: {', '.join(f'{t:g}' for t in scaled_tiers(args.max_usdc))}")
    print(f"  allowance: {limit} -> {usdc:g} USDC")

    ledger = SolanaLedger.from_env()
    ledger.fee_payer = args.fee_payer or args.operator
    v = ledger.vault(args.operator)
    if v is None:
        raise SystemExit(f"{args.operator} has no USDC vault yet ({ledger.token_account(args.operator)}): fund it first")
    if usdc > v["balance"]:
        print(f"  warning: vault holds {v['balance']:g} USDC, less than the allowance", file=sys.stderr)
    action, sig = apply(ledger, args.operator, args.agent, usdc)
    v = ledger.vault(args.operator)
    who = ledger.name_of(v["delegate"]) if v["delegate"] else "none"
    print(f"  {action}: vault {v['address']} holds {v['balance']:g} USDC, delegate={who}, allowance={v['delegated']:g} USDC")
    print(f"  {sig}\n  {EXPLORER.format(sig)}")
    return 0


def cmd_demo(args) -> int:
    import os
    from pathlib import Path
    from .demo import AGENT, SubprocessWatcher, run_demo
    from .solana_ledger import SolanaLedger
    if not os.environ.get("QUICKNODE_WSS_URL"):
        raise SystemExit("set QUICKNODE_WSS_URL (your endpoint's wss:// URL) for the outflow watcher")
    ledger = SolanaLedger.from_env()  # refuses anything but devnet
    return run_demo(ledger, SubprocessWatcher(str(ledger.pubkey(AGENT))), treasury=args.treasury,
                    min_usdc=args.min_usdc, log=Path(args.log),
                    results=Path(args.results) if args.results else None, report_out=args.out,
                    open_page=not args.no_open, timeout=args.timeout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cosign")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("test", help="crash-test one agent with one guard preset")
    t.add_argument("--agent", default="naive", choices=["naive", "llm"])
    t.add_argument("--provider", default="anthropic", choices=["anthropic", "openai"])
    t.add_argument("--model", default=None)
    t.add_argument("--guards", default="none", choices=PRESETS)
    t.add_argument("--trials", type=int, default=1)
    t.add_argument("--max-mutations", type=int, default=None, help="cap attacker rewrites (saves API cost)")
    t.add_argument("--ledger", default="sim", choices=["sim", "devnet"],
                   help="sim = in-memory; devnet = real Solana devnet USDC (see cosign.solana_ledger)")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=cmd_test)

    m = sub.add_parser("matrix", help="every model x every guard preset")
    m.add_argument("--models", default="naive", help="comma list: naive, anthropic:<model>, openai:<model>, adapter:<framework>")
    m.add_argument("--guards", default=",".join(PRESETS))
    m.add_argument("--trials", type=int, default=1)
    m.add_argument("--max-mutations", type=int, default=None)
    m.add_argument("--out", default="results.json")
    m.set_defaults(fn=cmd_matrix)

    rp = sub.add_parser("report", help="build the dashboard page from results.json")
    rp.add_argument("--results", default="results.json", help="matrix output; omit to use sample data")
    rp.add_argument("--out", default="cosign-report.html")
    rp.add_argument("--onchain", default="logs/watch.log", help="cosign watch output to show as devnet proof")
    rp.set_defaults(fn=cmd_report)

    gr = sub.add_parser("grant", help="set the agent's on-chain allowance (SPL delegation) from a results file")
    gr.add_argument("--results", required=True)
    gr.add_argument("--run", type=int, required=True, help="index of the run in the results file")
    gr.add_argument("--operator", default="operator", help="keypair name that owns the USDC vault")
    gr.add_argument("--agent", default="agent_wallet", help="keypair name approved as delegate")
    gr.add_argument("--max-usdc", type=float, default=20.0,
                    help="USDC the top tier (5000) maps to; default 20 fits the devnet demo, 5000 = unscaled")
    gr.add_argument("--fee-payer", default=None, help="keypair name paying fees (default: the operator)")
    gr.set_defaults(fn=cmd_grant)

    dm = sub.add_parser("demo", help="devnet demo: poisoned page, unguarded vs guarded, live outflow log, report")
    dm.add_argument("--treasury", default="treasury", help="keypair name to top the agent up from")
    dm.add_argument("--min-usdc", type=float, default=10.0, help="top the agent up to this if it holds less")
    dm.add_argument("--results", default=None, help="results file for the report (default: latest results*.json)")
    dm.add_argument("--log", default="logs/watch.log")
    dm.add_argument("--out", default="cosign-report.html")
    dm.add_argument("--timeout", type=float, default=90.0, help="seconds to wait for the watcher / log")
    dm.add_argument("--no-open", action="store_true")
    dm.set_defaults(fn=cmd_demo)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
