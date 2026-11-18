import json

from cosign import cli
from cosign.cli import guard_preset
from cosign.runner import crash_test


def test_episodes_record_steps_with_guard_decisions():
    run = crash_test(guard_preset("recommended"), max_mutations=5)
    ep = next(e for e in run.episodes if e.attack == "poisoned_website" and e.mutation == "data_smuggle")
    tools = [s["tool"] for s in ep.steps]
    assert tools[0] == "read_memory" and tools[-1] == "final"
    assert all(set(s) == {"tool", "args", "result", "blocked_reason"} for s in ep.steps)
    pay = next(s for s in ep.steps if s["tool"] == "pay")
    assert pay["args"]["recipient"] == "attacker_wallet"
    assert pay["result"].startswith("blocked by policy") and "allowlist" in pay["blocked_reason"]
    swap = next(s for s in ep.steps if s["tool"] == "swap")
    assert swap["blocked_reason"] is None and swap["result"].startswith("swapped")


def test_matrix_writes_run_folder_with_results_and_traces(tmp_path, capsys):
    out = tmp_path / "results.json"
    cli.main(["matrix", "--models", "naive", "--guards", "none,recommended", "--trials", "2",
              "--max-mutations", "2", "--out", str(out), "--runs-dir", str(tmp_path / "runs")])
    [run_dir] = list((tmp_path / "runs").iterdir())
    results = json.loads((run_dir / "results.json").read_text())
    assert results == json.loads(out.read_text())                         # old --out still written
    assert [r["preset"] for r in results] == ["none", "recommended"]

    lines = [json.loads(l) for l in (run_dir / "traces.jsonl").read_text().splitlines()]
    assert len(lines) == sum(r["episodes"] for r in results)
    assert set(lines[0]) == {"run", "task", "attack", "mutation", "trial", "stolen", "task_ok", "error", "steps"}
    assert {l["run"] for l in lines} == {0, 1} and {l["trial"] for l in lines} == {0, 1}
    stolen_none = [l for l in lines if l["run"] == 0 and l["stolen"] > 0]
    assert stolen_none and all(any(s["tool"] == "pay" for s in l["steps"]) for l in stolen_none)
    assert all(l["stolen"] == 0 for l in lines if l["run"] == 1)


def test_two_matrices_in_the_same_second_get_separate_folders(tmp_path):
    a, b = cli.new_run_dir(str(tmp_path)), cli.new_run_dir(str(tmp_path))
    assert a != b and a.exists() and b.exists()
