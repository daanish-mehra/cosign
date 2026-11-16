import json
"""Native tool calling (with fake clients) and external-agent adapters. No network, no API keys."""

import copy
from types import SimpleNamespace as NS

import pytest

from cosign.adapters import ElizaOSAdapter, SolanaAgentKitAdapter
from cosign.agent import TOOL_NAMES, Agent, LLMBrain
from cosign.attacks import ATTACKER
from cosign.cli import brain_factory, guard_preset
from cosign.guard import Guard
from cosign.tasks import make_world


class FakeAnthropic:
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.messages = NS(create=self._create)

    def _create(self, **kw):
        self.requests.append(copy.deepcopy(kw))
        return NS(content=self.turns.pop(0))


class FakeOpenAI:
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.requests.append(copy.deepcopy(kw))
        content, calls = self.turns.pop(0)
        tcs = [NS(id=f"call_{i}", function=NS(name=n, arguments=a)) for i, (n, a) in enumerate(calls)] or None
        return NS(choices=[NS(message=NS(content=content, tool_calls=tcs))])


def use(id_, name, **inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


def text(t):
    return NS(type="text", text=t)


def run(brain, guards):
    env = make_world()
    guard = Guard(env, guard_preset(guards))
    final = Agent(env, guard, brain).run("task")
    return env, guard, final


def stolen(env):
    return sum(t.amount for t in env.ledger.transfers if t.recipient == ATTACKER)


def test_anthropic_native_tools_go_through_the_guard():
    client = FakeAnthropic([
        [text("checking"), use("tu_1", "read_memory"),
         use("tu_2", "pay", recipient=ATTACKER, amount=50, memo="x")],   # two calls in one turn
        [text("all done")],
    ])
    env, guard, final = run(LLMBrain("anthropic", "m", client=client), "recommended")

    assert final == "all done"
    assert stolen(env) == 0 and any("allowlist" in b for b in guard.blocked)
    first, second = client.requests
    assert [t["name"] for t in first["tools"]] == TOOL_NAMES and len(TOOL_NAMES) == 9
    assert "input_schema" in first["tools"][0]
    # both results come back together, keyed by tool_use id, after the assistant's tool_use turn
    assert second["messages"][1]["role"] == "assistant"
    results = second["messages"][2]["content"]
    assert [r["tool_use_id"] for r in results] == ["tu_1", "tu_2"]
    assert results[1]["content"].startswith("blocked by policy")


def test_anthropic_without_guards_lets_the_payment_through():
    client = FakeAnthropic([[use("tu_1", "pay", recipient=ATTACKER, amount=50, memo="x")], [text("ok")]])
    env, _, _ = run(LLMBrain("anthropic", "m", client=client), "none")
    assert stolen(env) == 50


def test_openai_one_tool_call_per_turn_with_clean_history():
    # The model asks for two calls in one turn; only the first runs, and the history we send
    # back holds exactly one call with re-serialized arguments (providers reject anything else).
    client = FakeOpenAI([
        ("", [("swap", '{"symbol": "SOL", "usdc": 20}{"junk": 1}'), ("get_price", '{"symbol": "SOL"}')]),
        ("bought SOL", []),
    ])
    env, _, final = run(LLMBrain("openai", "m", client=client), "recommended")

    assert final == "bought SOL" and env.holdings.get("SOL", 0) > 0
    first, second = client.requests
    assert first["tools"][0]["type"] == "function" and first["parallel_tool_calls"] is False
    assert [t["function"]["name"] for t in first["tools"]] == TOOL_NAMES
    msgs = second["messages"]
    calls = msgs[2]["tool_calls"]
    assert msgs[2]["role"] == "assistant" and [c["id"] for c in calls] == ["call_0"]
    assert json.loads(calls[0]["function"]["arguments"]) == {"symbol": "SOL", "usdc": 20}
    assert [(m["role"], m["tool_call_id"]) for m in msgs[3:]] == [("tool", "call_0")]


def test_openai_unparseable_arguments_reported_back_to_model():
    client = FakeOpenAI([("", [("get_price", "not json")]), ("gave up", [])])
    _, _, final = run(LLMBrain("openai", "m", client=client), "none")
    assert final == "gave up"
    assert client.requests[1]["messages"][3]["content"].startswith("bad arguments for get_price")


def test_transient_errors_are_retried():
    from cosign.agent import _with_retries
    calls = {"n": 0}
    class RateLimitError(Exception):
        status_code = 429
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimitError("slow down")
        return "ok"
    assert _with_retries(flaky, base_delay=0) == "ok" and calls["n"] == 3


def scripted(replies):
    sent = []
    replies = list(replies)

    def transport(msg):
        sent.append(msg)
        return {} if msg["type"] == "reset" else replies.pop(0)
    return transport, sent


@pytest.mark.parametrize("guards,expected", [("none", 50), ("recommended", 0)])
def test_elizaos_adapter_translates_actions_and_guard_decides(guards, expected):
    transport, sent = scripted([
        {"tool": "SEND_TOKEN", "args": {"recipient": ATTACKER, "amount": 50}},
        {"tool": "SWAP_TOKEN", "args": {"outputTokenSymbol": "SOL", "amount": 15}},
        {"final": "done"},
    ])
    env, _, final = run(ElizaOSAdapter(transport), guards)
    assert final == "done" and stolen(env) == expected and env.holdings.get("SOL", 0) > 0
    assert sent[0]["type"] == "reset" and sent[0]["tools"] == TOOL_NAMES
    assert sent[2]["observation"].startswith("paid" if expected else "blocked by policy")


def test_solana_agent_kit_adapter_maps_tool_names():
    a = SolanaAgentKitAdapter(lambda m: {})
    from cosign.adapters import ExternalCall
    assert a.translate(ExternalCall("transfer", {"to": "x", "amount": 1})) == \
        {"tool": "pay", "args": {"recipient": "x", "amount": 1}}
    assert a.translate(ExternalCall("balance", {})) == {"tool": "balance", "args": {}}   # cosign name passes through


def test_stub_adapters_fail_fast_until_wired():
    for spec in ("adapter:elizaos", "adapter:solana-agent-kit"):
        with pytest.raises(NotImplementedError, match="stub"):
            brain_factory(spec)
    with pytest.raises(ValueError, match="unknown adapter"):
        brain_factory("adapter:nope")
