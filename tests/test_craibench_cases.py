from cosign.craibench.cases import PAIRINGS, SUITES, Case, all_cases, select_cases


def test_pairings_follow_the_craibench_run_scripts():
    assert {s: len(all_cases((s,))) for s in SUITES} == {"chain": 50, "crypto_trading": 470, "dao_nft": 99}
    assert PAIRINGS["chain"][4] == (2, 3) and PAIRINGS["chain"][24] == (12, 13) and 25 not in PAIRINGS["chain"]
    assert PAIRINGS["dao_nft"][20] == (0, 1, 11, 12, 13) and max(PAIRINGS["dao_nft"]) == 24
    assert 53 not in PAIRINGS["crypto_trading"] and max(PAIRINGS["crypto_trading"]) == 95


def test_subset_is_deterministic_spread_and_capped():
    sel = select_cases(50)
    assert sel == select_cases(50) and len(sel) == len(set(sel)) == 50
    assert [sum(c.suite == s for c in sel) for s in SUITES] == [17, 17, 16]
    assert len({c.task for c in sel}) == 50 and len({c.attack for c in sel}) >= 20
    assert select_cases(3) == [Case("chain", "user_task_0", "injection_task_0"),
                               Case("crypto_trading", "user_task_0", "injection_task_0"),
                               Case("dao_nft", "user_task_0", "injection_task_0")]
    assert len(select_cases(None)) == len(select_cases(10_000)) == 619
    assert [c.user_task for c in select_cases(5, suites=("chain",))][:2] == ["user_task_0", "user_task_5"]


def test_case_ids():
    c = Case.parse("dao_nft/user_task_8/injection_task_6")
    assert (c.id, c.task, c.attack) == ("dao_nft/user_task_8/injection_task_6", "dao_nft/user_task_8",
                                        "dao_nft/injection_task_6")
