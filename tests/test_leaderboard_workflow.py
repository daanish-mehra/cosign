"""The weekly leaderboard workflow: triggers, the secrets gate, one crash-test job per model, and the
deploy job that builds the site from every model's artifact. Each shell step is run for real (bash),
with nothing installed and no model called."""

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


def job(name):
    return load()["jobs"][name]


def step(job_name, name):
    return next(s for s in job(job_name)["steps"] if s.get("name") == name)


def uses(job_name, action):
    return next(s for s in job(job_name)["steps"] if s.get("uses", "").startswith(action))


def bash(script, cwd, **env):
    base = {"PATH": os.environ["PATH"], "HOME": str(cwd)}
    return subprocess.run(["bash", "-e", "-c", script], cwd=cwd, env=base | env, capture_output=True, text=True)


def read_models(cwd, tmp_path):
    out = tmp_path / "gh_output"
    out.write_text("")
    return bash(step("setup", "Read models")["run"], cwd, GITHUB_OUTPUT=str(out)), out


# --- triggers + secrets ----------------------------------------------------------
def test_weekly_cron_and_manual_trigger():
    on = load()[True]                         # YAML 1.1 reads the `on:` key as True
    assert on["schedule"] == [{"cron": "0 14 * * 1"}] and "workflow_dispatch" in on
    assert load()["permissions"] == {"contents": "read"}


def test_jobs_chain_setup_then_models_then_deploy():
    jobs = load()["jobs"]
    assert list(jobs) == ["setup", "crash-test", "deploy"]
    assert "needs" not in jobs["setup"]
    assert jobs["crash-test"]["needs"] == "setup" and jobs["deploy"]["needs"] == ["setup", "crash-test"]


def test_secrets_come_from_repo_secrets_and_each_job_gets_only_what_it_uses():
    ref = lambda n: f"${{{{ secrets.{n} }}}}"  # noqa: E731
    assert all(job("setup")["env"][n] == ref(n) for n in SECRETS)
    crash = job("crash-test")["env"]
    assert crash["OPENAI_API_KEY"] == ref("OPENAI_API_KEY") and crash["OPENAI_BASE_URL"] == ref("OPENAI_BASE_URL")
    assert "VERCEL_TOKEN" not in crash
    deploy = job("deploy")["env"]
    assert deploy["VERCEL_TOKEN"] == ref("VERCEL_TOKEN") and "OPENAI_API_KEY" not in deploy


def test_secrets_gate_runs_first_and_fails_without_spending(tmp_path):
    first = job("setup")["steps"][0]
    assert first["name"] == "Check secrets"
    gate = first["run"]
    r = bash(gate, tmp_path)
    assert r.returncode == 1 and "missing repo secrets: OPENAI_API_KEY OPENAI_BASE_URL VERCEL_TOKEN" in r.stdout
    r = bash(gate, tmp_path, OPENAI_API_KEY="k", OPENAI_BASE_URL="u")
    assert r.returncode == 1 and "missing repo secrets: VERCEL_TOKEN" in r.stdout
    r = bash(gate, tmp_path, **{n: "x" for n in SECRETS})
    assert r.returncode == 0 and "secrets present" in r.stdout


# --- models -> matrix ------------------------------------------------------------
def test_models_list_reads_web_models_txt_as_json(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "models.txt").write_text(
        "# comment\n\nmeta-llama/llama-3.1-8b-instruct\n  anthropic:claude-x  # inline comment\nqwen/q\n")
    r, out = read_models(tmp_path, tmp_path)
    assert r.returncode == 0, r.stderr
    line = out.read_text().strip()
    assert line.startswith("list=")
    assert json.loads(line.removeprefix("list=")) == [
        "openai:meta-llama/llama-3.1-8b-instruct", "anthropic:claude-x", "openai:qwen/q"]
    assert job("setup")["outputs"]["models"] == "${{ steps.models.outputs.list }}"

    (tmp_path / "web" / "models.txt").write_text("# nothing yet\n")
    r, _ = read_models(tmp_path, tmp_path)
    assert r.returncode == 1 and "lists no models" in r.stdout


def test_repo_models_txt_is_valid(tmp_path):
    r, out = read_models(ROOT, tmp_path)
    assert r.returncode == 0, r.stderr
    models = json.loads(out.read_text().strip().removeprefix("list="))
    assert len(models) >= 3 and all(m.startswith("openai:") and "/" in m for m in models)


def test_one_crash_test_job_per_model_four_at_a_time():
    s = job("crash-test")["strategy"]
    assert s["matrix"]["model"] == "${{ fromJSON(needs.setup.outputs.models) }}"
    assert s["max-parallel"] == 4 and s["fail-fast"] is False
    assert job("crash-test")["env"]["MODEL"] == "${{ matrix.model }}"
    run = step("crash-test", "Crash test")["run"]
    assert "cosign matrix" in run and '--models "$MODEL"' in run and "--techniques full" in run
    assert "--out results.json" in run and "--runs-dir runs" in run


def test_each_model_uploads_its_own_artifact(tmp_path):
    out = tmp_path / "gh_output"
    names = []
    for model in ("openai:meta-llama/llama-3.1-8b-instruct", "openai:amazon/nova-micro-v1"):
        out.write_text("")
        r = bash(step("crash-test", "Artifact name")["run"], tmp_path, MODEL=model, GITHUB_OUTPUT=str(out))
        assert r.returncode == 0, r.stderr
        names.append(out.read_text().strip().removeprefix("name="))
    assert names == ["results-openai-meta-llama-llama-3.1-8b-instruct", "results-openai-amazon-nova-micro-v1"]
    up = uses("crash-test", "actions/upload-artifact")["with"]
    assert up["name"] == "${{ steps.slug.outputs.name }}" and up["if-no-files-found"] == "error"
    assert "results.json" in up["path"] and "runs/" in up["path"]


# --- deploy ----------------------------------------------------------------------
def test_deploy_runs_after_the_models_even_if_some_failed():
    assert job("deploy")["if"] == "${{ !cancelled() && needs.setup.result == 'success' }}"
    dl = uses("deploy", "actions/download-artifact")["with"]
    assert dl == {"pattern": "results-*", "path": "results"}


def artifact(root, name, sample, traces):
    d = root / "results" / name
    (d / "runs" / "20261123T140000Z").mkdir(parents=True)
    (d / "results.json").write_text(json.dumps(sample))
    (d / "runs" / "20261123T140000Z" / "traces.jsonl").write_text(traces)


def test_build_step_builds_site_from_every_artifact(tmp_path):
    (tmp_path / "web").symlink_to(ROOT / "web")
    sample = json.loads((ROOT / "web" / "sample-results.json").read_text())
    traces = (ROOT / "web" / "sample-traces.jsonl").read_text()
    artifact(tmp_path, "results-openai-a", sample[:1], traces)
    artifact(tmp_path, "results-openai-b", sample[1:], traces)
    script = step("deploy", "Build site")["run"].replace("python web/", f"{sys.executable} web/")
    r = bash(script, tmp_path)
    assert r.returncode == 0, r.stderr
    kept = [x for x in sample if x.get("benign_utility", 0) > 0 or x.get("p_compromise", 0) > 0]
    assert f"built site/ with {len(kept)} runs" in r.stdout
    assert (tmp_path / "site" / "leaderboard.html").is_file()


def test_build_step_fails_when_no_model_produced_results(tmp_path):
    (tmp_path / "web").symlink_to(ROOT / "web")
    (tmp_path / "results").mkdir()
    r = bash(step("deploy", "Build site")["run"], tmp_path)
    assert r.returncode == 1 and "no model produced results" in r.stdout
    assert not (tmp_path / "site").exists()


def test_deploys_site_to_vercel_with_the_token():
    names = [s.get("name") for s in job("deploy")["steps"]]
    assert names.index("Build site") < names.index("Deploy to Vercel")
    run = step("deploy", "Deploy to Vercel")["run"]
    assert "vercel@" in run and "deploy site --prod" in run and '--token "$VERCEL_TOKEN"' in run
