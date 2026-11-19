"""Cosign CLI.

cosign test   --agent naive|llm [--provider anthropic|openai] [--model M] --guards PRESET [--ledger sim|devnet] [--techniques core|full]
cosign matrix --models naive,anthropic:MODEL,openai:MODEL,adapter:elizaos --guards none,caps,quarantine,recommended [--techniques core|full]
cosign techniques [--suite core|full]
cosign attest --results R --run N          cosign verify FILE [--pubkey K]
cosign policy --results R --run N [--format json|privy|turnkey]
cosign serve  [--runs-dir runs]           cosign doctor [--guard-url URL]
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
                     ledgers=ledgers, techniques=args.techniques)
    if ledgers is not None:
        swept = ledgers().sweep()
        print(f"devnet: swept {swept:g} USDC back to the treasury", file=sys.stderr)
    r = rate(run, cfg)
    if args.json:
        json.dump({"agent": spec, "guards": run.guard, "trials": run.trials, "mutations": run.mutations,
                   "techniques": run.techniques, **asdict(r)}, sys.stdout, indent=2)
        print()
    else:
        _print_report(spec, run.guard, r)
    return 0


def techniques_arg(value: str) -> str:
    """argparse type for --techniques: fail before any episode runs on a typo."""
    from .attacks import select_techniques
    try:
        select_techniques(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None
    return value


def cmd_techniques(args) -> int:
    from .attacks import select_techniques
    techs = select_techniques(args.suite)
    print(f"{'id':<46} {'channel':<16} {'payload':<17} {'obfuscation':<16} tasks")
    for t in techs:
        print(f"{t.id:<46} {t.channel:<16} {t.payload:<17} {t.obfuscation:<16} {','.join(t.targets)}")
    print(f"\n{len(techs)} techniques ({sum(t.core for t in techs)} core). "
          "Run a set with --techniques core|full|<id>,<id>")
    return 0


def run_key(agent: str, preset: str, taken: set[str] | None = None) -> str:
    """Joins a results row to its traces: "<agent>/<preset>", e.g. "naive/recommended".
    A repeat of the same pair in one matrix (pass the keys so far as `taken`) gets "#2", "#3", ..."""
    key, n = f"{agent}/{preset}", 2
    while taken is not None and key in taken:
        key, n = f"{agent}/{preset}#{n}", n + 1
    return key


def trace_lines(key: str, run) -> list[dict]:
    """One record per episode (benign first, then attacked), for runs/<ts>/traces.jsonl."""
    return [{"run": key, "task": e.task, "attack": e.attack, "mutation": e.mutation, "trial": e.trial,
             "stolen": e.stolen, "task_ok": e.task_ok, "error": e.error, "steps": e.steps}
            for e in run.benign + run.episodes]


def new_run_dir(root: str) -> "Path":
    from datetime import datetime, timezone
    from pathlib import Path
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d, n = Path(root) / stamp, 1
    while d.exists():  # two matrices in the same second
        d, n = Path(root) / f"{stamp}-{n}", n + 1
    d.mkdir(parents=True)
    return d


def cmd_matrix(args) -> int:
    rows, results = [], []
    run_dir = new_run_dir(args.runs_dir)
    (run_dir / "traces.jsonl").touch()
    for spec in [s.strip() for s in args.models.split(",") if s.strip()]:
        try:
            brains = brain_factory(spec)
        except (Exception, SystemExit) as e:  # missing key, package or model name
            print(f"skip {spec}: {e}", file=sys.stderr)
            continue
        for g in [p.strip() for p in args.guards.split(",") if p.strip()]:
            cfg = guard_preset(g)
            try:
                run = crash_test(cfg, brains, trials=args.trials, max_mutations=args.max_mutations,
                                 techniques=args.techniques)
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
            key = run_key(spec, g, {x["run"] for x in results})
            results.append({"run": key, "agent": spec, "guards": run.guard, "preset": g,
                            "trials": args.trials,
                            "mutations": run.mutations, "techniques": run.techniques,
                            "episodes": len(run.episodes) + len(run.benign),
                            **asdict(r)})
            with open(run_dir / "traces.jsonl", "a") as f:   # written as each run finishes
                for line in trace_lines(key, run):
                    f.write(json.dumps(line) + "\n")
            (run_dir / "results.json").write_text(json.dumps(results, indent=2))
            print(f"done {spec:<32} {g:<12} score={r.score:<3} limit={r.limit}", file=sys.stderr)

    print(f"\n{'agent':<32} {'guards':<12} {'score':>5} {'limit':>6} {'P':>5} {'loss':>5} {'util':>5}")
    print("-" * 76)
    for spec, g, r in rows:
        print(f"{spec:<32} {g:<12} {r.score:>5} {r.limit:>6} {r.p_compromise:>5.0%} "
              f"{r.lgd:>5.0%} {r.benign_utility:>5.0%}")
    (run_dir / "results.json").write_text(json.dumps(results, indent=2))
    print(f"\nsaved {run_dir}/results.json and traces.jsonl")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"saved {args.out}")
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

    row = load_run(args.results, args.run)
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
    from .demo import AGENT, SubprocessWatcher, run_demo, run_guarded_demo
    from .solana_ledger import SolanaLedger
    if args.guarded:
        return run_guarded_demo(SolanaLedger.from_env(), treasury=args.treasury, cosigner=args.cosigner,
                                min_usdc=args.min_usdc, guard_url=args.guard_url, run_id=args.run_id)
    if not os.environ.get("QUICKNODE_WSS_URL"):
        raise SystemExit("set QUICKNODE_WSS_URL (your endpoint's wss:// URL) for the outflow watcher")
    ledger = SolanaLedger.from_env()  # refuses anything but devnet
    return run_demo(ledger, SubprocessWatcher(str(ledger.pubkey(AGENT))), treasury=args.treasury,
                    min_usdc=args.min_usdc, log=Path(args.log),
                    results=Path(args.results) if args.results else None, report_out=args.out,
                    open_page=not args.no_open, timeout=args.timeout)


def load_run(results: str, index: int) -> dict:
    from pathlib import Path
    rows = json.loads(Path(results).read_text())
    rows = rows if isinstance(rows, list) else [rows]
    if not 0 <= index < len(rows):
        raise SystemExit(f"--run {index} out of range: {results} has {len(rows)} run(s)")
    return rows[index]


def cmd_attest(args) -> int:
    from pathlib import Path
    from .attest import attest, key_path
    env = attest(load_run(args.results, args.run))
    out = Path(args.out) if args.out else Path(args.results).parent / f"attestation-{args.run}.json"
    out.write_text(json.dumps(env, indent=2))
    p = env["payload"]
    print(f"{p['agent_id']}: score {p['score']}, limit {p['limit']}, expires {p['expires_at']}")
    for n in p["test_strength"]["notes"]:
        print(f"  note: {n}")
    print(f"wrote {out}  (signed by {env['public_key']}, key {key_path()})")
    return 0


def cmd_verify(args) -> int:
    from pathlib import Path
    from .attest import load_key, public_key_b64, verify
    env = json.loads(Path(args.file).read_text())
    trusted = args.pubkey
    if trusted is None:
        key = load_key(create=False)
        if key is None:
            raise SystemExit("no trusted key: pass --pubkey <issuer public key> (no local issuer key found)")
        trusted = public_key_b64(key)
    ok, reason = verify(env, trusted)
    p = env.get("payload", {})
    print(f"{'OK' if ok else 'INVALID'}: {reason}")
    if ok:
        print(f"  {p['agent_id']}  score {p['score']}  limit {p['limit']}  expires {p['expires_at']}")
    return 0 if ok else 1


def cmd_policy(args) -> int:
    from .policy import export
    addresses = {}
    for pair in args.address:
        name, sep, addr = pair.partition("=")
        if not (sep and name and addr):
            raise SystemExit(f"--address wants NAME=ADDRESS, got {pair!r}")
        addresses[name] = addr
    policy, notes = export(load_run(args.results, args.run), args.format, args.mint, addresses, args.signer)
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    text = json.dumps(policy, indent=2)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_serve(args) -> int:
    import uvicorn  # pip install -e .[api]
    from .api import create_app
    uvicorn.run(create_app(args.runs_dir), host=args.host, port=args.port)
    return 0


def cmd_doctor(args) -> int:
    from .doctor import main as doctor
    return doctor(guard_url=args.guard_url)


def cmd_vault(args) -> int:
    from .solana_ledger import TREASURY, SolanaLedger
    ledger = SolanaLedger.from_env()
    ledger.fee_payer = TREASURY
    if args.action == "create":
        v = ledger.create_multisig_vault(args.agent, args.cosigner)
        print(f"vault for {args.agent}: 2-of-2 SPL multisig ({args.agent} + {args.cosigner})"
              + ("" if v["created"] else ", already existed"))
        print(f"  agent          {ledger.pubkey(args.agent)}")
        print(f"  cosigner       {ledger.pubkey(args.cosigner)}")
        print(f"  multisig       {v['multisig']}")
        print(f"  token account  {v['token_account']}  ({v['balance']:g} USDC)")
        if v.get("signature"):
            print(f"  https://explorer.solana.com/tx/{v['signature']}?cluster=devnet")
    else:
        bal = ledger.fund_vault(args.agent, args.usdc)
        print(f"vault for {args.agent} holds {bal:g} USDC  ({ledger.multisig_vault(args.agent)['token_account']})")
    return 0


def cmd_guard(args) -> int:
    import uvicorn  # pip install -e .[api,solana]
    from .attest import load_key
    from .guard_service import Cosigner, create_app, runs_lookup
    from .solana_ledger import SolanaLedger
    ledger = SolanaLedger.from_env()
    cos = Cosigner(ledger, args.cosigner, load_key(), runs_lookup(args.runs_dir), args.log, args.allow)
    print(f"cosign guard: cosigner {cos.pubkey}, policies from {args.runs_dir}/, log {args.log}", file=sys.stderr)
    uvicorn.run(create_app(cos), host=args.host, port=args.port)
    return 0


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
    t.add_argument("--techniques", default="core", type=techniques_arg,
                   help="core (9 families, default), full (every technique), or comma-separated ids")
    t.set_defaults(fn=cmd_test)

    m = sub.add_parser("matrix", help="every model x every guard preset")
    m.add_argument("--models", default="naive", help="comma list: naive, anthropic:<model>, openai:<model>, adapter:<framework>")
    m.add_argument("--guards", default=",".join(PRESETS))
    m.add_argument("--trials", type=int, default=1)
    m.add_argument("--max-mutations", type=int, default=None)
    m.add_argument("--out", default="results.json")
    m.add_argument("--runs-dir", default="runs", help="each matrix writes <runs-dir>/<UTC timestamp>/")
    m.add_argument("--techniques", default="core", type=techniques_arg,
                   help="core (9 families, default), full (every technique), or comma-separated ids")

    tq = sub.add_parser("techniques", help="list the attack techniques and their ids")
    tq.add_argument("--suite", default="full", choices=["core", "full"])
    tq.set_defaults(fn=cmd_techniques)
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
    dm.add_argument("--guarded", action="store_true",
                    help="single-signer wallet vs 2-of-2 vault with cosign guard (no watcher or report)")
    dm.add_argument("--cosigner", default="cosigner", help="--guarded: cosigner keypair name")
    dm.add_argument("--guard-url", default=None, help="--guarded: a running `cosign guard serve` (default: in-process)")
    dm.add_argument("--run-id", default="naive/recommended", help="--guarded: run whose policy the guard enforces")
    dm.set_defaults(fn=cmd_demo)

    at = sub.add_parser("attest", help="write an ed25519-signed score/limit attestation for one run")
    at.add_argument("--results", required=True)
    at.add_argument("--run", type=int, required=True)
    at.add_argument("--out", default=None, help="default: attestation-<run>.json next to the results file")
    at.set_defaults(fn=cmd_attest)

    vf = sub.add_parser("verify", help="check an attestation's signature, issuer and expiry")
    vf.add_argument("file")
    vf.add_argument("--pubkey", default=None, help="trusted issuer public key (default: the local issuer key)")
    vf.set_defaults(fn=cmd_verify)

    po = sub.add_parser("policy", help="export a run's limit as a spending policy (cosign JSON, Privy or Turnkey)")
    po.add_argument("--results", required=True)
    po.add_argument("--run", type=int, required=True)
    from .policy import DEVNET_USDC, FORMATS
    po.add_argument("--format", choices=FORMATS, default="json")
    po.add_argument("--mint", default=DEVNET_USDC,
                    help="USDC mint for privy/turnkey (default: devnet USDC)")
    po.add_argument("--address", action="append", default=[], metavar="NAME=ADDRESS",
                    help="map an allowlist name to the recipient's USDC token account (repeatable)")
    po.add_argument("--signer", default=None, help="turnkey: the agent's Turnkey user id (sets consensus)")
    po.add_argument("--out", default=None)
    po.set_defaults(fn=cmd_policy)

    dr = sub.add_parser("doctor", help="check env keys, RPC/WSS, keypairs, devnet balances and the guard")
    dr.add_argument("--guard-url", default=None, help="also check that a running guard service answers here")
    dr.set_defaults(fn=cmd_doctor)

    sv = sub.add_parser("serve", help="limits API over the runs/ folder")
    sv.add_argument("--runs-dir", default="runs")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=cmd_serve)

    va = sub.add_parser("vault", help="devnet 2-of-2 vault: SPL multisig (agent + cosigner) owning a USDC account")
    vsub = va.add_subparsers(dest="action", required=True)
    vc = vsub.add_parser("create", help="create the multisig and its USDC token account, print the addresses")
    vc.add_argument("--agent", required=True, help="agent keypair name")
    vc.add_argument("--cosigner", required=True, help="cosigner keypair name (the one cosign guard holds)")
    vfund = vsub.add_parser("fund", help="top the vault up to --usdc from the treasury keypair")
    vfund.add_argument("--agent", default="agent_wallet")
    vfund.add_argument("--usdc", type=float, required=True)
    va.set_defaults(fn=cmd_vault)

    gd = sub.add_parser("guard", help="cosigner for 2-of-2 vaults: refuses transfers outside the earned policy")
    gsub = gd.add_subparsers(dest="action", required=True)
    gs = gsub.add_parser("serve", help="POST /v1/cosign: check an agent-signed transfer, cosign and submit or refuse")
    gs.add_argument("--cosigner", default="cosigner", help="keypair name of the cosigner (a vault member)")
    gs.add_argument("--runs-dir", default="runs", help="crash-test runs the policies come from")
    gs.add_argument("--log", default="logs/guard.log")
    gs.add_argument("--allow", action="append", default=[], metavar="NAME|ADDRESS",
                    help="recipients a tainted episode may pay when the policy has no allowlist (repeatable)")
    gs.add_argument("--host", default="127.0.0.1")
    gs.add_argument("--port", type=int, default=8100)
    gd.set_defaults(fn=cmd_guard)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
