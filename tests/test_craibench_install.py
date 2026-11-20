import pytest

from cosign.craibench import install as ins


def test_install_creates_a_pinned_separate_venv(tmp_path):
    cmds = []
    venv = tmp_path / "v"
    py = ins.install(venv, python="/x/python3.12", run=cmds.append, version_of=lambda p: "3.12")
    assert py == venv / "bin" / "python"
    assert cmds[0] == ["/x/python3.12", "-m", "venv", str(venv)]
    pip = cmds[1]
    assert pip[:4] == [str(py), "-m", "pip", "install"] and pip[-1] == ins.REQUIREMENT
    assert pip[pip.index("-c") + 1] == str(ins.CONSTRAINTS) and ins.CONSTRAINTS.exists()
    assert ins.COMMIT in ins.REQUIREMENT and len(ins.COMMIT) == 40
    assert "cohere==5.5.3" in ins.CONSTRAINTS.read_text().split()
    assert cmds[2][-1] == "import agentdojo.task_suite.load_suites"


def test_install_refuses_unsupported_python(tmp_path):
    with pytest.raises(SystemExit, match="supports 3.10-3.12"):
        ins.install(tmp_path / "v", python="py", run=lambda c: None, version_of=lambda p: "3.13")
    with pytest.raises(SystemExit, match="none is on PATH"):
        ins.find_base_python(which=lambda name: None)
    assert ins.find_base_python(which=lambda n: f"/bin/{n}" if n == "python3.11" else None) == "/bin/python3.11"


def test_bridge_python_lookup(tmp_path):
    assert ins.bridge_python({"COSIGN_CRAIBENCH_PYTHON": "/p"}, tmp_path) == "/p"
    with pytest.raises(SystemExit, match="cosign craibench install"):
        ins.bridge_python({}, tmp_path)
    py = tmp_path / ".venv-craibench" / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.touch()
    assert ins.bridge_python({}, tmp_path) == str(py)
    assert ins.bridge_command("/p") == ["/p", "-I", str(ins.BRIDGE)]


def test_cosign_never_depends_on_agentdojo():
    import tomllib
    from pathlib import Path
    meta = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())["project"]
    deps = meta["dependencies"] + [d for ds in meta["optional-dependencies"].values() for d in ds]
    assert not [d for d in deps if "agentdojo" in d or "CrAIBench" in d]
    bridge = ins.BRIDGE.read_text()
    assert "import cosign" not in bridge and "from cosign" not in bridge
