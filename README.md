# cosign

Crash-test an AI agent that holds money, get a score and a spend limit.

## Quickstart

**1. Install**

```sh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[llm,solana,attest,api,dev]"
```

**2. Check your setup**

```sh
cosign doctor
```

**3. Crash-test one agent**

```sh
cosign test --agent naive --guards recommended --trials 3
cosign test --agent llm --provider anthropic --guards recommended     # needs ANTHROPIC_API_KEY
```

**4. Every agent × every guard preset**

```sh
cosign matrix --models naive,anthropic:claude-haiku-5-5 --guards none,recommended --trials 3 --out results.json
```

**5. Sign a run's score and limit**

```sh
cosign attest --results results.json --run 1
cosign verify attestation-1.json
```

**6. Set the vault allowance on devnet**

```sh
cosign grant --results results.json --run 1
```

**7. Serve limits**

```sh
cosign serve --runs-dir runs        # GET /v1/agents, /v1/agents/{id}/limit
```

**8. Devnet demo: unguarded, then guarded**

```sh
export QUICKNODE_WSS_URL=wss://<your-devnet-endpoint>
cosign demo
```
