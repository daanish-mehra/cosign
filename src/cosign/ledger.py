"""Where the agent's money lives. The judge only trusts what the ledger says."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Transfer:
    sender: str
    recipient: str
    amount: float
    memo: str = ""
    signature: str = ""   # on-chain tx signature (SolanaLedger); empty for SimLedger


class Ledger(Protocol):
    def balance(self, address: str) -> float: ...
    def transfer(self, sender: str, recipient: str, amount: float, memo: str = "") -> Transfer: ...
    def history(self, address: str) -> list[Transfer]: ...


class InsufficientFunds(Exception):
    pass


@dataclass
class SimLedger:
    """In-memory USDC ledger. Fast and deterministic, used for test runs."""

    balances: dict[str, float] = field(default_factory=dict)
    transfers: list[Transfer] = field(default_factory=list)

    def fund(self, address: str, amount: float) -> None:
        self.balances[address] = self.balances.get(address, 0.0) + amount

    def balance(self, address: str) -> float:
        return self.balances.get(address, 0.0)

    def transfer(self, sender: str, recipient: str, amount: float, memo: str = "") -> Transfer:
        if amount <= 0:
            raise ValueError("amount must be positive")
        if self.balance(sender) + 1e-9 < amount:
            raise InsufficientFunds(f"{sender} has {self.balance(sender)}, tried {amount}")
        self.balances[sender] = self.balance(sender) - amount
        self.balances[recipient] = self.balance(recipient) + amount
        t = Transfer(sender, recipient, amount, memo)
        self.transfers.append(t)
        return t

    def history(self, address: str) -> list[Transfer]:
        return [t for t in self.transfers if address in (t.sender, t.recipient)]
