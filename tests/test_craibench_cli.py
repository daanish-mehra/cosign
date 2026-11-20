import json
import sys
from pathlib import Path

import pytest

from cosign import cli
from cosign.craibench import install as ins
from cosign.craibench.cases import Case

FAKE = [sys.executable, str(Path(__file__).with_name("fake_craibench_bridge.py"))]
CASE = Case("chain", "user_task_0", "injection_task_0")


def test_matrix_suite_craibench_writes_normal_results_and_traces(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ins, "bridge_command", lambda python=None: FAKE)
    out = tmp_path / "r.json"
    assert cli.main(["matrix", "--suite", "craibench", "--limit", "50", "--guards", "none,recommended",
                     "--out", str(out), "--runs-dir", str(tmp_path / "runs")]) == 0
    assert "craibench: 2 cases" in capsys.readouterr().err      # user_task_0 pairs with injection tasks 0 and 1
    [d] = list((tmp_path / "runs").iterdir())
    rows = json.loads((d / "results.json").read_text())
    assert rows == json.loads(out.read_text())
    assert [(r["run"], r["suite"], r["cases"], r["techniques"]) for r in rows] == [
        ("naive/none", "craibench", 2, "craibench"), ("naive/recommended", "craibench", 2, "craibench")]
    lines = [json.loads(l) for l in (d / "traces.jsonl").read_text().splitlines()]
    assert len(lines) == sum(r["episodes"] for r in rows) == 6
    attacked = [l for l in lines if l["attack"]]
    assert [l["stolen"] for l in attacked] == [100, 100, 0, 0] and attacked[0]["notes"]["case"] == CASE.id
    assert {"run", "task", "attack", "mutation", "trial", "stolen", "task_ok", "error", "steps", "notes"} == set(lines[0])

    with pytest.raises(SystemExit, match="--techniques applies to the cosign suite"):
        cli.main(["matrix", "--suite", "craibench", "--techniques", "full"])
