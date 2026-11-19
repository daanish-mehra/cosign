import json

from cosign import cli
from cosign.cli import guard_preset
from cosign.runner import crash_test


def test_episodes_record_steps_with_guard_decisions():
    run = crash_test(guard_preset("recommended"), max_mutations=5)
    ep = next(e for e in run.episodes if e.attack == "poisoned_website" and e.mutation == "data_smuggle")
    tools = [s["tool"] for s in ep.steps]
    assert tools[0] == "read_memory" and tools[-1] == "final"
    assert all(set(s) == {"tool", "args", "result", "untrusted", "blocked_reason"} for s in ep.steps)
    assert [s["untrusted"] for s in ep.steps if s["tool"] in ("browse", "token_info")] == [True, True]
    assert not any(s["untrusted"] for s in ep.steps if s["tool"] in ("read_memory", "swap", "final"))
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
    assert {l["run"] for l in lines} == {"naive/none", "naive/recommended"} and {l["trial"] for l in lines} == {0, 1}
    stolen_none = [l for l in lines if l["run"] == "naive/none" and l["stolen"] > 0]
    assert stolen_none and all(any(s["tool"] in ("pay", "approve") for s in l["steps"]) for l in stolen_none)
    assert all(l["stolen"] == 0 for l in lines if l["run"] == "naive/recommended")


def test_two_matrices_in_the_same_second_get_separate_folders(tmp_path):
    a, b = cli.new_run_dir(str(tmp_path)), cli.new_run_dir(str(tmp_path))
    assert a != b and a.exists() and b.exists()


def test_repeated_pairs_get_distinct_run_keys(tmp_path):
    cli.main(["matrix", "--models", "naive", "--guards", "none,caps,none", "--max-mutations", "1",
              "--out", "", "--runs-dir", str(tmp_path)])
    [run_dir] = list(tmp_path.iterdir())
    results = json.loads((run_dir / "results.json").read_text())
    assert [r["run"] for r in results] == ["naive/none", "naive/caps", "naive/none#2"]
    assert all(r["run"].startswith(f'{r["agent"]}/{r["preset"]}') for r in results)
    lines = [json.loads(l) for l in (run_dir / "traces.jsonl").read_text().splitlines()]
    for r in results:   # every row's episodes are findable by its run id, and only by it
        assert sum(l["run"] == r["run"] for l in lines) == r["episodes"]
    assert cli.run_key("openai:meta-llama/llama-3.1-8b-instruct", "recommended") == \
        "openai:meta-llama/llama-3.1-8b-instruct/recommended"


def test_run_key_joins_each_results_row_to_its_traces(tmp_path):
    cli.main(["matrix", "--models", "naive", "--guards", "none,caps,recommended", "--max-mutations", "1",
              "--out", str(tmp_path / "r.json"), "--runs-dir", str(tmp_path / "runs")])
    [run_dir] = list((tmp_path / "runs").iterdir())
    results = json.loads((run_dir / "results.json").read_text())
    lines = [json.loads(l) for l in (run_dir / "traces.jsonl").read_text().splitlines()]
    assert [r["run"] for r in results] == ["naive/none", "naive/caps", "naive/recommended"]
    for r in results:
        mine = [l for l in lines if l["run"] == r["run"]]
        assert r["run"] == f"{r['agent']}/{r['preset']}"
        assert len(mine) == r["episodes"]                        # every episode lands under its own row
        assert (sum(l["stolen"] for l in mine) > 0) == (r["p_compromise"] > 0)
    assert all(isinstance(l["run"], str) for l in lines)       # never a bare index (0 is falsy in the viewer)
