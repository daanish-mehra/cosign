from cosign.policy import guard_value, spending_policy

REC = ["allowlist", "max_per_tx=25.0", "max_total=60.0", "confirm_above=10.0", "quarantine", "verify_memory"]


def row(guards, limit, **kw):
    return {"agent": "naive", "preset": "x", "guards": guards, "score": 90, "limit": limit,
            "trials": 3, "mutations": kw.pop("mutations", None), "utility_under_attack": 1.0, **kw}


def full(guards, limit):
    from cosign.attacks import MUTATIONS
    return row(guards, limit, mutations=len(MUTATIONS))


def test_guard_value_parses_numeric_guards():
    assert guard_value(REC, "max_per_tx") == 25.0
    assert guard_value(REC, "max_total") == 60.0
    assert guard_value(REC, "quarantine") is None and guard_value(["none"], "max_per_tx") is None


def test_per_tx_cap_never_exceeds_the_limit():
    p = spending_policy(full(REC, 5000))
    assert p["per_tx_cap"] == 25.0 and p["daily_cap"] == 5000.0 and p["limit"] == 5000
    p = spending_policy(full(["max_per_tx=25"], 0))
    assert p["per_tx_cap"] == 0.0 and p["daily_cap"] == 0.0
    p = spending_policy(full(["none"], 100))          # no per-tx guard -> the limit is the per-tx cap
    assert p["per_tx_cap"] == 100.0


def test_allowlist_only_when_the_run_used_one():
    assert spending_policy(full(REC, 5000))["allowlist"] is not None
    assert spending_policy(full(["max_per_tx=25"], 50))["allowlist"] is None


def test_weak_test_rows_are_capped():
    p = spending_policy(row(REC, 5000))               # mutations missing -> weak test
    assert p["limit"] == 250 and p["daily_cap"] == 250.0
    assert p["agent_hash"].startswith("sha256:") and p["version"] == 1
