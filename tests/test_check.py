"""cosign.check: the pre-signing client a wallet calls. Local attestations and the limits API, each rule,
and failing closed. No network."""

import json
import math
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from cosign.attacks import ATTACKER, MUTATIONS  # noqa: E402
from cosign.attest import agent_id, public_key_b64, sign  # noqa: E402
from cosign.check import Checker, Decision, check  # noqa: E402
from cosign.policy import signed_limit  # noqa: E402

REC = ["allowlist", "max_per_tx=25.0", "max_total=60.0", "confirm_above=10.0", "quarantine", "verify_memory",
       "max_slippage_bps=100", "taint"]
T0 = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
VENDOR_ADDR = "So1VendorAddr1111111111111111111111111111111"


def row(guards=REC, limit=5000, agent="openai:openai/gpt-4o-mini"):
    return {"agent": agent, "preset": "recommended", "guards": guards, "score": 100, "limit": limit,
            "trials": 3, "mutations": len(MUTATIONS), "utility_under_attack": 1.0}


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def local(key):
    r = row()
    aid = agent_id(r)
    env = signed_limit(r, key, T0)
    checker = Checker(attestation=env, trusted_key=public_key_b64(key), clock=lambda: T0 + timedelta(hours=1))
    return checker, aid, env


def test_allowlisted_payment_under_the_caps_is_allowed(local):
    checker, aid, env = local
    d = checker.check(aid, {"to": "dex_pool", "amount": 5})
    assert isinstance(d, Decision) and d and d.reason == "5 USDC transfer to dex_pool within policy"
    assert d.policy == env["payload"]["policy"]
    assert checker(aid, {"to": "forecast_api", "amount": 25, "kind": "transfer"}).allow


def test_allowlist(local):
    checker, aid, _ = local
    d = checker.check(aid, {"to": ATTACKER, "amount": 1})
    assert not d and d.reason == f"recipient {ATTACKER} is not on the allowlist"


def test_allowlist_names_map_to_addresses(local):
    checker, aid, _ = local
    checker.addresses = {"DVnd7Kq2xPm4R9sWQ2Rx": VENDOR_ADDR}
    assert checker.check(aid, {"to": VENDOR_ADDR, "amount": 3}).allow


def test_per_tx_and_daily_caps(local):
    checker, aid, _ = local
    assert checker.check(aid, {"to": "dex_pool", "amount": 26}).reason == "26 USDC is over the per-tx cap of 25"
    checker.spent_today = lambda a: 4990.0
    d = checker.check(aid, {"to": "dex_pool", "amount": 20})
    assert d.reason == "over the daily cap: 4990 USDC spent today, +20 > 5000"


def test_zero_limit_denies_everything(key):
    r = row(limit=0)
    checker = Checker(attestation=signed_limit(r, key, T0), trusted_key=public_key_b64(key), clock=lambda: T0)
    assert checker.check(agent_id(r), {"to": "dex_pool", "amount": 1}).reason.startswith("limit is 0")


def test_every_money_move_is_checked_by_what_it_risks(local):
    checker, aid, _ = local
    c = lambda tx: checker.check(aid, tx).reason  # noqa: E731
    assert c({"to": "dex_pool", "amount": math.inf, "kind": "approve"}) == \
        "unlimited USDC at risk (approve) is over the per-tx cap of 25"
    assert c({"to": ATTACKER, "amount": 5, "kind": "approve"}) == f"spender {ATTACKER} is not on the allowlist"
    assert checker.check(aid, {"to": "dex_pool", "amount": 5, "kind": "approve"}).allow
    assert c({"to": "dex_pool", "amount": 1, "kind": "authority", "balance": 100}) == \
        "100 USDC at risk (authority) is over the per-tx cap of 25"
    assert c({"to": ATTACKER, "amount": 1, "kind": "authority"}) == f"new authority {ATTACKER} is not on the allowlist"
    assert c({"to": "dex_pool", "amount": 1, "kind": "recurring", "every_days": 1}) == \
        "30 USDC at risk (recurring) is over the per-tx cap of 25"
    assert checker.check(aid, {"to": "dex_pool", "amount": 5, "kind": "recurring", "every_days": 7}).allow
    assert c({"to": ATTACKER, "amount": 2, "kind": "bridge"}) == f"bridge destination {ATTACKER} is not on the allowlist"
    assert checker.check(aid, {"to": "forecast_api", "amount": 2, "kind": "bridge"}).allow


def test_swap_slippage_cap(local):
    checker, aid, _ = local
    d = checker.check(aid, {"to": "dex_pool", "amount": 20, "kind": "swap", "slippage_bps": 5000})
    assert d.reason == "swap slippage 5000 bps is over the cap of 100 bps"
    assert checker.check(aid, {"to": "dex_pool", "amount": 20, "kind": "swap", "slippage_bps": 100}).allow
    assert checker.check(aid, {"to": "dex_pool", "amount": 20, "kind": "swap"}).allow   # default 50 bps
    assert checker.check(aid, {"to": ATTACKER, "amount": 1, "kind": "swap"}).reason == \
        f"pool {ATTACKER} is not on the allowlist"


def test_fails_closed_on_bad_input(local):
    checker, aid, _ = local
    assert checker.check(aid, {"to": "dex_pool", "amount": 1, "kind": "mint"}).reason == "unknown kind 'mint'"
    for tx in ({"amount": 1}, {"to": "dex_pool"}, {"to": "dex_pool", "amount": -1}, {"to": "dex_pool", "amount": "x"},
               "not a dict"):
        assert not checker.check(aid, tx)


def test_attestation_must_verify_and_match(local, key, tmp_path):
    checker, aid, env = local
    assert checker.check("someone-else--recommended", {"to": "dex_pool", "amount": 1}).reason == \
        f"attestation is for {aid}, not someone-else--recommended"

    forged = json.loads(json.dumps(env))
    forged["payload"]["policy"]["per_tx_cap"] = 10 ** 9
    assert checker.check(aid, {"to": "dex_pool", "amount": 1}).allow
    checker.attestation = forged
    assert checker.check(aid, {"to": "dex_pool", "amount": 1}).reason.startswith("attestation rejected: bad signature")

    other = Ed25519PrivateKey.generate()
    checker.attestation = signed_limit(row(), other, T0)              # validly signed, wrong issuer
    assert checker.check(aid, {"to": "dex_pool", "amount": 1}).reason == "attestation rejected: signed by an untrusted key"

    checker.attestation = signed_limit(row(), key, T0)
    checker.clock = lambda: T0 + timedelta(days=8)
    assert checker.check(aid, {"to": "dex_pool", "amount": 1}).reason.startswith("attestation rejected: expired")

    checker.clock = lambda: T0
    checker.attestation = sign({"agent_id": aid, "issued_at": "2026-11-20T12:00:00Z",
                                "expires_at": "2026-11-27T12:00:00Z"}, key)   # an attestation, but no policy
    assert checker.check(aid, {"to": "dex_pool", "amount": 1}).reason == "attestation carries no spending policy"

    path = tmp_path / "limit.json"
    path.write_text(json.dumps(signed_limit(row(), key, T0)))         # a local file works like a dict
    assert check(aid, {"to": "dex_pool", "amount": 1}, attestation=str(path), trusted_key=public_key_b64(key),
                 clock=lambda: T0).allow


def test_limits_api_is_fetched_and_failures_deny(key):
    r = row()
    aid = agent_id(r)
    urls = []

    def fetch(url):
        urls.append(url)
        return signed_limit(r, key, T0)

    checker = Checker(api="https://limits.example/", trusted_key=public_key_b64(key), fetch=fetch, clock=lambda: T0)
    assert checker.check(aid, {"to": "dex_pool", "amount": 1}).allow
    assert urls == [f"https://limits.example/v1/agents/{aid}/limit"]

    def down(url):
        raise OSError("connection refused")
    checker.fetch = down
    d = checker.check(aid, {"to": "dex_pool", "amount": 1})
    assert not d and d.reason == f"no signed limit for {aid}: OSError: connection refused"
    assert not Checker().check(aid, {"to": "dex_pool", "amount": 1})   # nothing configured


def test_against_the_real_limits_api(key, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from cosign.api import create_app
    r = row()
    (tmp_path / "20261120T120000Z").mkdir()
    (tmp_path / "20261120T120000Z" / "results.json").write_text(json.dumps([r]))
    client = TestClient(create_app(tmp_path, key))
    fetch = lambda url: client.get(url.removeprefix("http://limits")).json()  # noqa: E731
    checker = Checker(api="http://limits", trusted_key=public_key_b64(key), fetch=fetch)
    assert checker.check(agent_id(r), {"to": "dex_pool", "amount": 5}).allow
    assert not checker.check(agent_id(r), {"to": ATTACKER, "amount": 5})
    assert checker.check("nobody--none", {"to": "dex_pool", "amount": 5}).reason.startswith("attestation rejected")
