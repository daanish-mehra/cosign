"""Which CrAIBench (user task, injection task) pairs are valid, and a cheap deterministic subset.

The pairings are CrAIBench's own, from its run scripts at commit e41eac1 (prompt injection, not memory
injection): run_script.sh for chain, run_script_dao.sh for dao_nft, run_crypto_task.sh for crypto_trading
(every user task with every injection task).
"""

from __future__ import annotations

from dataclasses import dataclass

SUITES = ("chain", "crypto_trading", "dao_nft")


def _expand(groups: list[tuple[range | tuple[int, ...], tuple[int, ...]]]) -> dict[int, tuple[int, ...]]:
    return {u: injs for users, injs in groups for u in users}


# user task number -> injection task numbers. Prompt-injection runs use user tasks 0-24 (25+ are single-step
# tasks the scripts reserve for memory injection).
CHAIN = _expand([(range(0, 4), (0, 1)), (range(4, 7), (2, 3)), (range(7, 11), (4, 5)), (range(11, 15), (6, 7)),
                 (range(15, 19), (8, 9)), (range(19, 21), (10, 11)), (range(21, 25), (12, 13))])
DAO_NFT = _expand([(range(0, 4), (0, 1, 2, 3, 4)), (range(4, 8), (0, 1, 5)), (range(8, 12), (0, 1, 6, 7)),
                   (range(12, 16), (0, 1, 8, 9)), (range(16, 20), (0, 1, 10)), (range(20, 24), (0, 1, 11, 12, 13)),
                   (range(24, 25), (0, 1, 14))])
CRYPTO_TRADING = _expand([(tuple(u for u in range(96) if u not in (53, 54)), (0, 1, 2, 3, 4))])  # 53, 54 don't exist
PAIRINGS = {"chain": CHAIN, "crypto_trading": CRYPTO_TRADING, "dao_nft": DAO_NFT}


@dataclass(frozen=True, order=True)
class Case:
    suite: str
    user_task: str
    injection_task: str

    @property
    def id(self) -> str:
        return f"{self.suite}/{self.user_task}/{self.injection_task}"

    @property
    def task(self) -> str:       # Episode.task / PairResult.task
        return f"{self.suite}/{self.user_task}"

    @property
    def attack(self) -> str:     # Episode.attack / PairResult.attack (the family in the attack grid)
        return f"{self.suite}/{self.injection_task}"

    @classmethod
    def parse(cls, text: str) -> "Case":
        suite, user, inj = text.split("/")
        return cls(suite, user, inj)


def all_cases(suites: tuple[str, ...] = SUITES) -> list[Case]:
    return [Case(s, f"user_task_{u}", f"injection_task_{i}")
            for s in suites for u, injs in sorted(PAIRINGS[s].items()) for i in injs]


def select_cases(limit: int | None = 50, suites: tuple[str, ...] = SUITES) -> list[Case]:
    """`limit` cases split evenly across the suites, evenly spaced within each suite so the subset covers
    many user tasks and every injection family. Same input, same cases."""
    per_suite = {s: all_cases((s,)) for s in suites}
    if limit is None or limit >= sum(map(len, per_suite.values())):
        return [c for s in suites for c in per_suite[s]]
    out: list[Case] = []
    for k, s in enumerate(suites):
        n = limit // len(suites) + (1 if k < limit % len(suites) else 0)
        pool = per_suite[s]
        n = min(n, len(pool))
        out += [pool[(j * len(pool)) // n] for j in range(n)] if n else []
    return out
