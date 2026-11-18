import json

import pytest

from cosign import cli
from cosign.attacks import MUTATIONS
from cosign.tasks import VENDOR
from cosign.policy import DEVNET_USDC, export, privy_policy, spending_policy, turnkey_policy

REC = ["allowlist", "max_per_tx=25.0", "max_total=60.0", "confirm_above=10.0", "quarantine", "verify_memory"]


def row(guards=REC, limit=5000):
    return {"agent": "naive", "preset": "recommended", "guards": guards, "score": 100, "limit": limit,
            "trials": 3, "mutations": len(MUTATIONS), "utility_under_attack": 1.0}


def test_privy_rule_caps_amount_mint_and_destination():
    pol = spending_policy(row())
    out, notes = privy_policy(pol, addresses={"dex_pool": "DexTokenAcct111"})
    assert out["version"] == "1.0" and out["chain_type"] == "solana"
    [rule] = out["rules"]
    assert rule["action"] == "ALLOW" and rule["method"] == "signAndSendTransaction"
    conds = {c["field"]: c for c in rule["conditions"]}
    assert all(c["field_source"] == "solana_token_program_instruction" for c in conds.values())
    assert conds["TransferChecked.mint"]["value"] == DEVNET_USDC
    assert conds["TransferChecked.amount"] == {**conds["TransferChecked.amount"], "operator": "lte", "value": "25000000"}
    assert conds["TransferChecked.destination"]["value"] == [VENDOR, "DexTokenAcct111", "forecast_api"]
    assert any("'forecast_api' is a test name" in n for n in notes)
    assert not any("'dex_pool'" in n for n in notes)
    assert any("daily_cap" in n for n in notes)


def test_privy_without_allowlist_and_zero_limit():
    out, _ = privy_policy(spending_policy(row(["max_per_tx=25"], 50)))
    assert "TransferChecked.destination" not in {c["field"] for c in out["rules"][0]["conditions"]}
    out, _ = privy_policy(spending_policy(row(["none"], 0)))
    assert out["rules"] == []                                    # privy default-denies


def test_turnkey_condition_and_consensus():
    pol = spending_policy(row())
    out, notes = turnkey_policy(pol, mint="MintX", signer="user-123",
                                addresses={"dex_pool": "A1", "forecast_api": "B2", VENDOR: "C3"})
    assert out["effect"] == "EFFECT_ALLOW"
    assert out["consensus"] == "approvers.any(user, user.id == 'user-123')"
    c = out["condition"]
    assert "solana.tx.spl_transfers.all(transfer, " in c and "solana.tx.transfers.count() == 0" in c
    assert "transfer.token_mint == 'MintX'" in c and "transfer.amount <= 25000000" in c
    assert "transfer.to in ['C3', 'A1', 'B2']" in c
    assert not any("test name" in n for n in notes) and not any("consensus" in n for n in notes)

    out, notes = turnkey_policy(spending_policy(row(["none"], 0)))
    assert out["effect"] == "EFFECT_DENY" and "consensus" not in out
    assert any("no --signer" in n for n in notes)


def test_export_dispatch():
    assert export(row())[0] == spending_policy(row())
    with pytest.raises(ValueError):
        export(row(), "fireblocks")


def test_cli_formats(tmp_path, capsys):
    results = tmp_path / "r.json"
    results.write_text(json.dumps([row()]))
    cli.main(["policy", "--results", str(results), "--run", "0", "--format", "privy",
              "--address", "dex_pool=AAA", "--address", "forecast_api=BBB", "--address", f"{VENDOR}=CCC"])
    cap = capsys.readouterr()
    p = json.loads(cap.out)
    assert p["rules"][0]["conditions"][-1]["value"] == ["CCC", "AAA", "BBB"] and "test name" not in cap.err

    out = tmp_path / "tk.json"
    cli.main(["policy", "--results", str(results), "--run", "0", "--format", "turnkey",
              "--signer", "u1", "--out", str(out)])
    assert json.loads(out.read_text())["consensus"].endswith("'u1')")
    with pytest.raises(SystemExit):
        cli.main(["policy", "--results", str(results), "--run", "0", "--address", "nope"])
