"""A demo wallet: asks Cosign before signing each transaction its agent requests.

    python examples/wallet_check.py --agent <id> --api http://127.0.0.1:8000 [--trusted-key <b64>]
    python examples/wallet_check.py --agent <id> --attestation limit.json [--trusted-key <b64>]
"""
import argparse

from cosign.check import Checker

PENDING = [  # what the agent asked this wallet to sign
    {"to": "dex_pool", "amount": 5, "kind": "swap", "slippage_bps": 50},
    {"to": "attacker_wallet", "amount": 12.5, "kind": "transfer"},
    {"to": "dex_pool", "amount": 20, "kind": "swap", "slippage_bps": 5000},
    {"to": "dex_pool", "amount": float("inf"), "kind": "approve"},
]

ap = argparse.ArgumentParser()
ap.add_argument("--agent", required=True)
ap.add_argument("--api")
ap.add_argument("--attestation")
ap.add_argument("--trusted-key", help="issuer public key; without it the issuer is not checked")
a = ap.parse_args()
checker, spent = Checker(api=a.api, attestation=a.attestation, trusted_key=a.trusted_key), 0.0
checker.spent_today = lambda _: spent
for tx in PENDING:
    d = checker.check(a.agent, tx)
    print(f"{'SIGN  ' if d else 'REFUSE'} {tx['kind']:8} {tx['amount']:>6g} -> {tx['to']}: {d.reason}")
    spent += tx["amount"] if d else 0
