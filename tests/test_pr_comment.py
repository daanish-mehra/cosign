import json
from dataclasses import asdict

from cosign import pr_comment
from cosign.cli import guard_preset
from cosign.pr_comment import MARKER, format_comment
from cosign.runner import crash_test
from cosign.scoring import rate


def row(preset, trials=1, agent="naive"):
    cfg = guard_preset(preset)
    run = crash_test(cfg, trials=trials)
    return json.loads(json.dumps({"agent": agent, "guards": run.guard, "trials": trials,
                                  "mutations": run.mutations, **asdict(rate(run, cfg))}))


CAPS, REC = row("caps"), row("recommended", trials=3)


def test_regression_against_main():
    c = format_comment(CAPS, REC)
    lines = c.splitlines()
    assert lines[0] == MARKER and lines[1] == "## Cosign crash test"
    assert "**Score 0/100** (▼ −100 vs `main`) · **Spend limit 0 USDC** (was 5000)" in c
    assert "agent `naive` · guards `max_per_tx=25, max_total=60` · 1 trial · 6/6 attacker rewrites" in c
    assert "⚠️ weak test" in c
    assert "| Attack | This PR | `main` |\n|---|---|---|" in c
    assert "| `memory_poisoning` | 🔴 breached 4/4 via `small_amount` | 🟢 held 0/4 |" in c
    assert len([l for l in lines if l.startswith("| `")]) == 5


def test_improvement_and_top_three_fixes():
    none = row("none")
    assert len(none["fixes"]) > 3
    c = format_comment(REC, none, base_name="release")
    assert "(▲ +100 vs `release`)" in c and "(was 0)" in c and "weak test" not in c
    assert "_None needed: every attack held._" in c
    fixes = [l for l in format_comment(none, REC).splitlines() if l[:3] in ("1. ", "2. ", "3. ", "4. ")]
    assert [f[:3] for f in fixes] == ["1. ", "2. ", "3. "] and fixes[0].endswith(none["fixes"][0])


def test_no_baseline_and_no_change():
    c = format_comment(REC)
    assert "vs `main`" not in c and "_No baseline from `main`, so no comparison._" in c
    assert "| Attack | This PR |\n|---|---|" in c
    assert "(= ±0 vs `main`)" in format_comment(REC, REC) and "(was" not in format_comment(REC, REC)


def test_cells_are_escaped_and_families_unique_to_one_side_show():
    head = {**REC, "agent": "a|b", "by_family": {"x|y": [1, 2, "w|z"]}, "fixes": []}
    base = {**REC, "by_family": {"gone": [0, 1, None]}}
    c = format_comment(head, base)
    assert "agent `a\\|b`" in c
    assert "| `x\\|y` | 🔴 breached 1/2 via `w\\|z` | – |" in c and "| `gone` | – | 🟢 held 0/1 |" in c
    assert "_No fixes suggested._" in c


def test_cli_matrix_files_and_outputs(tmp_path):
    head = tmp_path / "head.json"
    head.write_text(json.dumps([CAPS, {**REC, "agent": "other"}]))
    base = tmp_path / "base.json"
    base.write_text(json.dumps([{**REC, "agent": "other"}, REC]))   # matched by agent + guards, not index
    out, gh = tmp_path / "c.md", tmp_path / "gh_output"
    assert pr_comment.main(["--head", str(head), "--base", str(base), "--run", "1",
                            "--out", str(out), "--github-output", str(gh)]) == 0
    assert out.read_text() == format_comment({**REC, "agent": "other"}, {**REC, "agent": "other"})
    assert gh.read_text() == f"score=100\nlimit=5000\nscore_delta=0\n"

    empty = tmp_path / "empty.json"
    empty.write_text("")
    pr_comment.main(["--head", str(head), "--base", str(empty), "--out", str(out), "--github-output", str(gh)])
    assert "No baseline" in out.read_text() and gh.read_text().endswith("score_delta=\n")
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    pr_comment.main(["--head", str(head), "--base", str(bad), "--out", str(out)])
    assert "No baseline" in out.read_text()


def test_action_runs_this_script_and_reads_its_outputs():
    import re
    from pathlib import Path

    import pytest
    yaml = pytest.importorskip("yaml")
    action_dir = Path(__file__).parent.parent / ".github" / "actions" / "cosign"
    action = yaml.safe_load((action_dir / "action.yml").read_text())
    steps = {s.get("name") or s.get("uses"): s for s in action["runs"]["steps"]}
    assert action["runs"]["using"] == "composite"
    assert all("shell" in s for s in steps.values() if "run" in s)

    fmt = steps["Format comment"]
    script = fmt["env"]["PR_COMMENT"].replace("${{ github.action_path }}", str(action_dir))
    assert Path(script).resolve() == Path(pr_comment.__file__).resolve()
    assert "--github-output" in fmt["run"] and "--base-name" in fmt["run"]
    written = {"score", "limit", "score_delta"}
    assert {re.search(r"outputs\.(\w+)", o["value"]).group(1) for o in action["outputs"].values()} == written
    assert MARKER in steps["Post comment"]["run"]
