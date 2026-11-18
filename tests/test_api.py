import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from cosign import cli  # noqa: E402
from cosign.api import create_app  # noqa: E402
from cosign.attest import attest, load_key  # noqa: E402
from cosign.attacks import MUTATIONS  # noqa: E402
from cosign.policy import spending_policy  # noqa: E402
from cosign.tasks import VENDOR  # noqa: E402

LLAMA = "openai:meta-llama/llama-3.1-8b-instruct"
REC = ["allowlist", "max_per_tx=25.0", "max_total=60.0", "confirm_above=10.0", "quarantine", "verify_memory"]


def row(preset, guards, score, limit, **kw):
    return {"agent": LLAMA, "preset": preset, "guards": guards, "score": score, "limit": limit,
            "trials": 3, "mutations": len(MUTATIONS), "utility_under_attack": 0.9, **kw}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(tmp_path / "key.json"))
    runs = tmp_path / "runs"
    (runs / "20261117T120000Z").mkdir(parents=True)
    (runs / "20261117T120000Z" / "results.json").write_text(json.dumps(
        [row("recommended", REC, 80, 1000), row("none", ["none"], 10, 0, utility_under_attack=0.2)]))
    (runs / "20261118T090000Z").mkdir()
    (runs / "20261118T090000Z" / "results.json").write_text(json.dumps([row("recommended", REC, 92, 5000)]))
    (runs / "broken").mkdir()
    (runs / "broken" / "results.json").write_text("{not json")
    return TestClient(create_app(runs))


REC_ID = "openai-meta-llama-llama-3-1-8b-instruct--recommended"


def test_list_uses_latest_run_per_agent(client):
    agents = {a["id"]: a for a in client.get("/v1/agents").json()}
    assert set(agents) == {REC_ID, "openai-meta-llama-llama-3-1-8b-instruct--none"}
    assert agents[REC_ID]["score"] == 92 and agents[REC_ID]["run"] == "20261118T090000Z"


def test_agent_detail_carries_a_verifiable_attestation(client):
    d = client.get(f"/v1/agents/{REC_ID}").json()
    assert d["score"] == 92 and d["limit"] == 5000 and d["test_strength"]["full"]
    v = client.post("/v1/attest/verify", json=d["attestation"]).json()
    assert v["valid"] and v["payload"]["agent_id"] == REC_ID

    forged = d["attestation"]; forged["payload"]["limit"] = 10 ** 6
    v = client.post("/v1/attest/verify", json=forged).json()
    assert not v["valid"] and v["payload"] is None
    assert client.get("/v1/agents/nope").status_code == 404


def test_signed_limit_for_wallets(client):
    env = client.get(f"/v1/agents/{REC_ID}/limit").json()
    p = env["payload"]
    assert p["limit"] == 5000 and p["policy"]["daily_cap"] == 5000 and p["policy"]["per_tx_cap"] == 25
    assert p["policy"]["allowlist"] == sorted(["dex_pool", "forecast_api", VENDOR])
    assert client.post("/v1/attest/verify", json=env).json()["valid"]
    none = client.get("/v1/agents/openai-meta-llama-llama-3-1-8b-instruct--none/policy").json()
    assert none["daily_cap"] == 0 and none["per_tx_cap"] == 0 and none["allowlist"] is None
    issuer = client.get("/v1/issuer").json()["public_key"]
    assert env["public_key"] == issuer


def test_policy_export_cli(tmp_path, capsys):
    results = tmp_path / "r.json"
    results.write_text(json.dumps([row("recommended", REC, 92, 5000, mutations=None)]))
    cli.main(["policy", "--results", str(results), "--run", "0"])
    p = json.loads(capsys.readouterr().out)
    assert p == spending_policy(json.loads(results.read_text())[0])
    assert p["daily_cap"] == 250 and p["per_tx_cap"] == 25          # weak test -> capped


def test_serve_runs_uvicorn_on_the_runs_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("COSIGN_ATTEST_KEY", str(tmp_path / "key.json"))
    import uvicorn
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port: seen.update(app=app, host=host, port=port))
    assert cli.main(["serve", "--runs-dir", str(tmp_path), "--port", "9001"]) == 0
    assert seen["host"] == "127.0.0.1" and seen["port"] == 9001
    assert TestClient(seen["app"]).get("/v1/agents").json() == []
