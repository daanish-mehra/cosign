"""CrAIBench (github.com/AthaSSiN/CrAIBench, built on AgentDojo) run through cosign's judge and guards.

CrAIBench lives in its own venv (`cosign craibench install`); cosign talks to it through bridge.py over
stdio, so its dependencies never touch cosign's. `cosign matrix --suite craibench --limit 50` runs a
deterministic subset of its Web3 (user task, injection task) pairs.
"""
