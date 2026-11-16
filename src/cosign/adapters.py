"""Crash-test an external agent (one cosign didn't build) by wrapping it as a Brain.

The external agent never touches money directly. Each turn it gets the latest tool result and
answers with what it wants to do, in its own vocabulary (e.g. Solana Agent Kit's "transfer" or
ElizaOS's "SEND_TOKEN"). The adapter translates that into a cosign Action; Agent._call then runs
it through the same Guard and sandbox as every other brain. So the rating covers the external
agent's reasoning, and cosign's guards (not the framework's own wallet code) decide what moves.

To plug in a new framework, subclass BrainAdapter and implement:
    reset(task_prompt, tools)  -> start a fresh session with the task and the 9 cosign tools
    step(observation)          -> send the last tool result, return the agent's next move as
                                  ExternalCall(name, args) or ExternalFinal(text)
and fill TOOL_MAP with {framework tool name: (cosign tool, {framework arg: cosign arg})}.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from .agent import TOOL_SPECS, Action


@dataclass
class ExternalCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExternalFinal:
    text: str


ExternalMove = ExternalCall | ExternalFinal
ToolMap = dict[str, tuple[str, dict[str, str]]]


class BrainAdapter(ABC):
    """Base class: implements the Brain protocol (start/next) on top of reset/step."""

    name: str = "external"
    TOOL_MAP: ToolMap = {}

    @abstractmethod
    def reset(self, task_prompt: str, tools: list[dict[str, Any]]) -> None:
        """Start a fresh session for one episode."""

    @abstractmethod
    def step(self, observation: str | None) -> ExternalMove:
        """Give the agent the last tool result (None on the first turn); return its next move."""

    # --- Brain protocol ------------------------------------------------------
    def start(self, task_prompt: str) -> None:
        self.reset(task_prompt, TOOL_SPECS)

    def next(self, observation: str | None) -> Action:
        move = self.step(observation)
        if isinstance(move, ExternalFinal):
            return {"final": move.text}
        return self.translate(move)

    def translate(self, call: ExternalCall) -> Action:
        """Framework tool call -> cosign Action. Unknown tools are passed through by name, so the
        Agent answers 'unknown tool' instead of silently doing something else."""
        if call.name in self.TOOL_MAP:
            tool, renames = self.TOOL_MAP[call.name]
            return {"tool": tool, "args": {renames.get(k, k): v for k, v in call.args.items()}}
        return {"tool": call.name, "args": dict(call.args)}


Transport = Callable[[dict[str, Any]], dict[str, Any]]
"""Sends one JSON message to the external agent's runtime and returns its JSON reply.
Reply shape the stubs expect: {"tool": name, "args": {...}} or {"final": text}."""


class _TransportAdapter(BrainAdapter):
    """Shared plumbing for adapters that talk to an out-of-process agent via a Transport."""

    wiring_hint = ""

    def __init__(self, transport: Transport | None = None):
        if transport is None:
            raise NotImplementedError(f"{self.name} adapter is a stub: pass transport=... ({self.wiring_hint})")
        self.transport = transport
        self.session: dict[str, Any] = {}

    def reset(self, task_prompt: str, tools: list[dict[str, Any]]) -> None:
        self.session = {"task": task_prompt, "tools": [t["name"] for t in tools]}
        self.transport({"type": "reset", **self.session})

    def step(self, observation: str | None) -> ExternalMove:
        reply = self.transport({"type": "step", "observation": observation})
        if "final" in reply:
            return ExternalFinal(str(reply["final"]))
        return ExternalCall(str(reply.get("tool", "")), dict(reply.get("args") or {}))


class SolanaAgentKitAdapter(_TransportAdapter):
    """STUB. Solana Agent Kit (sendaifun) runs in its own process (usually TypeScript + LangChain).
    Wire it with a small bridge that exposes cosign's tools to the kit in place of its real
    on-chain actions, and relays each call here through `transport`.

    Tool names below follow the kit's action naming; check them against the version you run."""

    name = "solana-agent-kit"
    wiring_hint = "e.g. HTTP to a Node bridge that hosts the kit's LangChain agent"
    TOOL_MAP: ToolMap = {
        "transfer": ("pay", {"to": "recipient", "amount": "amount", "memo": "memo"}),
        "trade": ("swap", {"outputMint": "symbol", "inputAmount": "usdc"}),
        "fetch_price": ("get_price", {"tokenId": "symbol", "tokenAddress": "symbol"}),
        "get_balance": ("balance", {}),
        "get_token_data": ("token_info", {"symbol": "symbol", "tokenSymbol": "symbol"}),
    }


class ElizaOSAdapter(_TransportAdapter):
    """STUB. ElizaOS agents run as a Node server and act through named Actions. Wire it with a
    plugin that registers cosign's tools as Actions and forwards each invocation here through
    `transport` instead of executing it.

    Action names below follow ElizaOS Solana plugin naming; check them against your plugin."""

    name = "elizaos"
    wiring_hint = "e.g. HTTP to an ElizaOS server running a cosign bridge plugin"
    TOOL_MAP: ToolMap = {
        "SEND_TOKEN": ("pay", {"recipient": "recipient", "amount": "amount", "memo": "memo"}),
        "SWAP_TOKEN": ("swap", {"outputTokenSymbol": "symbol", "amount": "usdc"}),
        "GET_PRICE": ("get_price", {"symbol": "symbol"}),
        "GET_BALANCE": ("balance", {}),
    }


ADAPTERS: dict[str, type[_TransportAdapter]] = {
    SolanaAgentKitAdapter.name: SolanaAgentKitAdapter,
    ElizaOSAdapter.name: ElizaOSAdapter,
}
