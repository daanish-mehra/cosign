"""The weekly leaderboard workflow: triggers, the secrets gate, the models list and the site build.
Each shell step is run for real (bash), with nothing installed and no model called."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "leaderboard.yml"
SECRETS = ("OPENAI_API_KEY", "OPENAI_BASE_URL", "VERCEL_TOKEN")


def load():
    return yaml.safe_load(WORKFLOW.read_text())


def steps():
    return load()["jobs"]["leaderboard"]["steps"]


def step(name):
    return next(s for s in steps() if s.get("name") == name)


def bash(script, cwd, **env):
    base = {"PATH": os.environ["PATH"], "HOME": str(cwd)}
    return subprocess.run(["bash", "-e", "-c", script], cwd=cwd, env=base | env, capture_output=True, text=True)


def test_weekly_cron_and_manual_trigger():
    on = load()[True]                         # YAML 1.1 reads the `on:` key as True
    assert on["schedule"] == [{"cron": "0 14 * * 1"}] and "workflow_dispatch" in on
    assert load()["permissions"] == {"contents": "read"}


def test_secrets_come_from_repo_secrets():
    env = load()["jobs"]["leaderboard"]["env"]
    for name in SECRETS:
        assert env[name] == f"${{{{ secrets.{name} }}}}"


def test_secrets_gate_runs_first_and_fails_without_spending(tmp_path):
    names = [s.get("name") or s.get("uses") for s in steps()]
    assert names[0] == "Check secrets"
    gate = step("Check secrets")["run"]
    r = bash(gate, tmp_path)
    assert r.returncode == 1 and "missing repo secrets: OPENAI_API_KEY OPENAI_BASE_URL VERCEL_TOKEN" in r.stdout
    r = bash(gate, tmp_path, OPENAI_API_KEY="k", OPENAI_BASE_URL="u")
    assert r.returncode == 1 and "missing repo secrets: VERCEL_TOKEN" in r.stdout
    r = bash(gate, tmp_path, **{n: "x" for n in SECRETS})
    assert r.returncode == 0 and "secrets present" in r.stdout


def test_models_list_reads_web_models_txt(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "models.txt").write_text(
        "# comment\n\nmeta-llama/llama-3.1-8b-instruct\n  anthropic:claude-x  # inline comment\nqwen/q\n")
    out = tmp_path / "out"
    r = bash(step("Read models")["run"], tmp_path, GITHUB_OUTPUT=str(out))
    assert r.returncode == 0, r.stderr
    assert out.read_text() == "list=openai:meta-llama/llama-3.1-8b-instruct,anthropic:claude-x,openai:qwen/q\n"

    (tmp_path / "web" / "models.txt").write_text("# nothing yet\n")
    r = bash(step("Read models")["run"], tmp_path, GITHUB_OUTPUT=str(out))
    assert r.returncode == 1 and "lists no models" in r.stdout


def test_repo_models_txt_is_valid(tmp_path):
    out = tmp_path / "out"
    r = bash(step("Read models")["run"], ROOT, GITHUB_OUTPUT=str(out))
    assert r.returncode == 0, r.stderr
    models = out.read_text().strip().removeprefix("list=").split(",")
    assert len(models) >= 3 and all(m.startswith("openai:") and "/" in m for m in models)


def test_crash_test_runs_the_full_suite_on_those_models():
    run = step("Crash test")["run"]
    assert "cosign matrix" in run and "--techniques full" in run
    assert '--models "${{ steps.models.outputs.list }}"' in run and "--out results-leaderboard.json" in run


def test_build_step_builds_site_from_the_run(tmp_path):
    (tmp_path / "web").symlink_to(ROOT / "web")
    sample = json.loads((ROOT / "web" / "sample-results.json").read_text())
    (tmp_path / "results-leaderboard.json").write_text(json.dumps(sample))
    (tmp_path / "runs" / "20261123T140000Z").mkdir(parents=True)
    (tmp_path / "runs" / "20261123T140000Z" / "traces.jsonl").write_text(
        (ROOT / "web" / "sample-traces.jsonl").read_text())
    r = bash(step("Build site")["run"].replace("python ", f"{sys.executable} "), tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "site" / "leaderboard.html").is_file() and "built site/" in r.stdout


def test_deploys_site_to_vercel_with_the_token():
    run = step("Deploy to Vercel")["run"]
    assert "vercel@" in run and "deploy site --prod" in run and '--token "$VERCEL_TOKEN"' in run
    names = [s.get("name") for s in steps()]
    assert names.index("Crash test") < names.index("Build site") < names.index("Deploy to Vercel")
