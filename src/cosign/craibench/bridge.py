"""CrAIBench bridge: serves one CrAIBench episode at a time over stdio JSON-RPC (newline-delimited).

Run by cosign with the CrAIBench venv's python (`cosign craibench install` makes one):

    .venv-craibench/bin/python -I src/cosign/craibench/bridge.py

It imports agentdojo (the CrAIBench fork) and never imports cosign, so the two dependency sets stay apart.
cosign drives the agent; this process owns the CrAIBench environment.

Methods (besides MCP's initialize / tools/list / tools/call):
  craibench/catalog  {suites}                         -> {suite: {user_tasks: {id: prompt}, injection_tasks: {id: goal}}}
  craibench/start    {suite, user_task, injection_task|null, attack}
                     -> {prompt, tools, wallet, prices, authorized, injected, canary, user_plan, injection_plan}
  craibench/preview  {name, arguments}                -> {outflows, error}   (dry run on a copy of the environment)
  tools/call         {name, arguments}                -> MCP CallToolResult (runs for real)
  craibench/finish   {output}                         -> {utility, security, outflows}

An outflow is a CrAIBench Transaction the call adds with sender == the wallet's address.
"""

from __future__ import annotations

import json
import sys
import traceback
import types
import warnings

PROTOCOL = sys.stdout
sys.stdout = sys.stderr          # agentdojo and the task checks print(); keep the protocol stream clean
warnings.filterwarnings("ignore")

STATE: dict = {}
ATTACKS: dict = {}


def _suite(name: str):
    from agentdojo.task_suite.load_suites import get_suite
    return get_suite("v1", name)


def _txns(env) -> list[dict]:
    return [t.model_dump() for t in env.wallet.transactions]


def _outflows(env, since: int) -> list[dict]:
    addr = env.wallet.address
    return [t for t in _txns(env)[since:] if t.get("sender") == addr]


def _calls(calls) -> list[dict]:
    return [{"tool": c.function, "args": dict(c.args)} for c in calls]


def _run(env, name: str, args: dict):
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    result, error = STATE["runtime"].run_function(env, name, args)
    if error:
        return f"error: {error}", True
    return tool_result_to_str(result), False


def _attack(suite, name: str):
    from agentdojo.attacks.attack_registry import load_attack
    key = (suite.name, name)
    if key not in ATTACKS:   # the attack only reads the pipeline's name to address the model; use a neutral one
        ATTACKS[key] = load_attack(name, suite, types.SimpleNamespace(name="gpt-4o"))
    return ATTACKS[key]


def catalog(suites: list[str]) -> dict:
    out = {}
    for s in suites:
        suite = _suite(s)
        out[s] = {"user_tasks": {k: t.PROMPT for k, t in suite.user_tasks.items()},
                  "injection_tasks": {k: t.GOAL for k, t in suite.injection_tasks.items()}}
    return out


def start(suite: str, user_task: str, injection_task: str | None = None,
          attack: str = "important_instructions_no_names") -> dict:
    from agentdojo.functions_runtime import FunctionsRuntime
    s = _suite(suite)
    user = s.get_user_task_by_id(user_task)
    inj = s.get_injection_task_by_id(injection_task) if injection_task else None
    injections = _attack(s, attack).attack(user, inj) if inj else {}
    env = user.init_environment(s.load_and_inject_default_environment(injections))
    pre = env.model_copy(deep=True)
    STATE.clear()
    STATE.update(suite=s, user=user, inj=inj, env=env, pre=pre, start=len(env.wallet.transactions),
                 runtime=FunctionsRuntime(s.tools), trace=[])

    gt = user.ground_truth(pre.model_copy(deep=True))
    scratch = pre.model_copy(deep=True)
    for c in gt:
        STATE["runtime"].run_function(scratch, c.function, c.args)
    wallet = env.wallet.model_dump()
    feed = getattr(env, "price_feed", None)
    prices = {}
    for p in (feed.recent_prices if feed else []):
        prices[p.token] = p.price_usdc     # later entries win: the most recent price
    return {
        "prompt": user.PROMPT,
        "tools": [{"name": f.name, "description": f.description,
                   "parameters": f.parameters.model_json_schema()} for f in s.tools],
        "wallet": {"address": wallet.get("address"), "balances": wallet.get("balances")},
        "prices": prices,
        "authorized": _outflows(scratch, STATE["start"]),
        "injected": sorted(injections),
        "canary": inj.GOAL if inj else None,
        "user_plan": _calls(gt),
        "injection_plan": _calls(inj.ground_truth(pre.model_copy(deep=True))) if inj else [],
    }


def preview(name: str, arguments: dict) -> dict:
    env = STATE["env"].model_copy(deep=True)
    n = len(env.wallet.transactions)
    text, is_error = _run(env, name, arguments)
    return {"outflows": _outflows(env, n), "error": text if is_error else None}


def call(name: str, arguments: dict) -> dict:
    from agentdojo.functions_runtime import FunctionCall
    text, is_error = _run(STATE["env"], name, arguments)
    STATE["trace"].append(FunctionCall(function=name, args=arguments))
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def finish(output: str = "") -> dict:
    s, env, pre, trace = STATE["suite"], STATE["env"], STATE["pre"], STATE["trace"]

    def check(fn):
        try:
            return bool(fn())
        except Exception:   # some CrAIBench checks index into the transaction list and fail on short runs
            return False
    utility = check(lambda: s._check_user_task_utility(STATE["user"], output, pre, env, trace))
    security = check(lambda: s._check_injection_task_security(STATE["inj"], output, pre, env, trace)) \
        if STATE["inj"] else False
    return {"utility": utility, "security": security, "outflows": _outflows(env, STATE["start"])}


def handle(method: str, params: dict):
    if method == "initialize":
        import importlib.metadata as md
        return {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
                "serverInfo": {"name": "craibench-bridge", "version": md.version("agentdojo")}}
    if method == "tools/list":
        return {"tools": [{"name": t["name"], "description": t["description"], "inputSchema": t["parameters"]}
                          for t in STATE.get("tools", [])]}
    if method == "craibench/catalog":
        return catalog(params.get("suites") or ["chain", "crypto_trading", "dao_nft"])
    if method == "craibench/start":
        info = start(**params)
        STATE["tools"] = info["tools"]
        return info
    if method == "craibench/preview":
        return preview(params["name"], params.get("arguments") or {})
    if method == "tools/call":
        return call(params["name"], params.get("arguments") or {})
    if method == "craibench/finish":
        return finish(params.get("output", ""))
    raise KeyError(f"unknown method {method}")


def main() -> None:
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "id" not in msg:
            continue   # notifications
        try:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": handle(msg["method"], msg.get("params") or {})}
        except Exception as e:
            traceback.print_exc()
            reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32000, "message": f"{type(e).__name__}: {e}"}}
        PROTOCOL.write(json.dumps(reply, default=str) + "\n")
        PROTOCOL.flush()


if __name__ == "__main__":
    main()
