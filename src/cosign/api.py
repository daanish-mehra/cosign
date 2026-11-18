"""Limits API (`cosign serve`). Reads every runs/<timestamp>/results.json; the newest run wins.

GET  /v1/agents                 agents with their latest score and limit
GET  /v1/agents/{id}            latest score, limit, run info and a fresh signed attestation
GET  /v1/agents/{id}/limit      signed limit + spending policy, for wallets (valid 7 days)
GET  /v1/agents/{id}/policy     the spending policy alone (unsigned JSON export)
POST /v1/attest/verify          verify an attestation against this server's issuer key
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .attest import VALID_FOR, _iso, agent_id, attest, load_key, public_key_b64, sign, verify
from .grant import effective_limit
from .policy import spending_policy


def latest_runs(runs_dir: Path) -> dict[str, dict]:
    """agent id -> {"row", "run", "index"} from the newest run folder that contains it."""
    out: dict[str, dict] = {}
    for d in sorted(p for p in runs_dir.glob("*") if (p / "results.json").is_file()):
        try:
            rows = json.loads((d / "results.json").read_text())
        except json.JSONDecodeError:
            continue
        for i, row in enumerate(rows if isinstance(rows, list) else []):
            if isinstance(row, dict) and "agent" in row and "limit" in row:
                out[agent_id(row)] = {"row": row, "run": d.name, "index": i}
    return out


def create_app(runs_dir: str | Path = "runs", key=None):
    from fastapi import Body, FastAPI, HTTPException

    runs = Path(runs_dir)
    key = key or load_key()
    app = FastAPI(title="Cosign limits API", version="1")

    def find(agent: str) -> dict:
        hit = latest_runs(runs).get(agent)
        if hit is None:
            raise HTTPException(404, f"unknown agent {agent}")
        return hit

    @app.get("/v1/agents")
    def agents():
        return [{"id": aid, "agent": h["row"]["agent"], "guards": h["row"].get("guards"),
                 "score": h["row"]["score"], "limit": effective_limit(h["row"])[0],
                 "run": h["run"], "run_index": h["index"]}
                for aid, h in sorted(latest_runs(runs).items())]

    @app.get("/v1/agents/{agent}")
    def agent_detail(agent: str):
        h = find(agent)
        row = h["row"]
        env = attest(row, key)
        return {"id": agent, "agent": row["agent"], "guards": row.get("guards"), "score": row["score"],
                "limit": env["payload"]["limit"], "test_strength": env["payload"]["test_strength"],
                "run": h["run"], "run_index": h["index"], "attestation": env}

    @app.get("/v1/agents/{agent}/limit")
    def agent_limit(agent: str):
        row = find(agent)["row"]
        now = datetime.now(timezone.utc)
        policy = spending_policy(row)
        return sign({"agent_id": agent, "agent_hash": policy["agent_hash"], "limit": policy["limit"],
                     "policy": policy, "issued_at": _iso(now), "expires_at": _iso(now + VALID_FOR)}, key)

    @app.get("/v1/agents/{agent}/policy")
    def agent_policy(agent: str):
        return spending_policy(find(agent)["row"])

    @app.post("/v1/attest/verify")
    def verify_attestation(env: dict = Body(...)):
        ok, reason = verify(env, public_key_b64(key))
        return {"valid": ok, "reason": reason, "payload": env.get("payload") if ok else None}

    @app.get("/v1/issuer")
    def issuer():
        return {"alg": "ed25519", "public_key": public_key_b64(key)}

    return app
