"""Install CrAIBench into its own venv, and find the python that runs the bridge.

CrAIBench can't share cosign's environment: it needs Python 3.10-3.12 and pins anthropic 0.28 / openai 1.31,
older than cosign's `llm` extra allows. So it gets a venv of its own, pinned to one commit and installed with
the versions from its own requirements.lock (constraints.txt next to this file).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

REPO = "https://github.com/AthaSSiN/CrAIBench"
COMMIT = "e41eac1eb2fea00a31c69827bfe83f9722a25702"
REQUIREMENT = f"agentdojo @ git+{REPO}@{COMMIT}"
DEFAULT_VENV = ".venv-craibench"
SUPPORTED = ("3.12", "3.11", "3.10")
CONSTRAINTS = Path(__file__).with_name("constraints.txt")
BRIDGE = Path(__file__).with_name("bridge.py")

Run = Callable[[list[str]], None]


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def venv_python(venv: str | Path) -> Path:
    return Path(venv) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def find_base_python(which: Callable[[str], str | None] = shutil.which) -> str:
    for v in SUPPORTED:
        found = which(f"python{v}")
        if found:
            return found
    raise SystemExit(f"CrAIBench needs Python {SUPPORTED[-1]}-{SUPPORTED[0]} and none is on PATH. "
                     "Install one, or pass --python /path/to/python3.12")


def python_version(python: str) -> str:
    out = subprocess.run([python, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def install(venv: str | Path = DEFAULT_VENV, python: str | None = None, run: Run = _run,
            version_of: Callable[[str], str] = python_version) -> Path:
    base = python or find_base_python()
    v = version_of(base)
    if v not in SUPPORTED:
        raise SystemExit(f"{base} is Python {v}; CrAIBench supports {SUPPORTED[-1]}-{SUPPORTED[0]}")
    py = venv_python(venv)
    if not py.exists():
        run([base, "-m", "venv", str(venv)])
    run([str(py), "-m", "pip", "install", "--quiet", "-c", str(CONSTRAINTS), REQUIREMENT])
    run([str(py), "-I", "-c", "import agentdojo.task_suite.load_suites"])   # fails loudly if an import broke
    return py


def bridge_python(env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    """COSIGN_CRAIBENCH_PYTHON, else ./.venv-craibench's python."""
    env = os.environ if env is None else env
    if env.get("COSIGN_CRAIBENCH_PYTHON"):
        return env["COSIGN_CRAIBENCH_PYTHON"]
    py = (cwd or Path.cwd()) / venv_python(DEFAULT_VENV)
    if py.exists():
        return str(py)
    raise SystemExit("CrAIBench isn't installed: run `cosign craibench install` "
                     "(or set COSIGN_CRAIBENCH_PYTHON to a python that has it)")


def bridge_command(python: str | None = None) -> list[str]:
    return [python or bridge_python(), "-I", str(BRIDGE)]
