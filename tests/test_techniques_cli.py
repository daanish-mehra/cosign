import json

import pytest

from cosign import cli
from cosign.attacks import CORE_TECHNIQUES, TECHNIQUES


def test_test_command_records_the_suite(capsys):
    cli.main(["test", "--guards", "recommended", "--json"])
    core = json.loads(capsys.readouterr().out)
    assert core["techniques"] == "core" and set(core["by_family"]) == {t.id for t in CORE_TECHNIQUES}

    cli.main(["test", "--guards", "recommended", "--json", "--techniques", "full"])
    full = json.loads(capsys.readouterr().out)
    assert full["techniques"] == "full" and set(full["by_family"]) == {t.id for t in TECHNIQUES}
    assert full["score"] < core["score"] == 100

    cli.main(["test", "--json", "--techniques", "invoice.recurring.plain,poisoned_website", "--max-mutations", "1"])
    picked = json.loads(capsys.readouterr().out)
    assert list(picked["by_family"]) == ["invoice.recurring.plain", "poisoned_website"]


def test_matrix_rows_record_the_suite(tmp_path):
    out = tmp_path / "r.json"
    cli.main(["matrix", "--guards", "none", "--techniques", "full", "--out", str(out),
              "--runs-dir", str(tmp_path / "runs")])
    [row] = json.loads(out.read_text())
    assert row["techniques"] == "full" and len(row["by_family"]) == len(TECHNIQUES)


def test_bad_technique_fails_before_running(capsys):
    with pytest.raises(SystemExit):
        cli.main(["matrix", "--techniques", "core,nope"])
    assert "unknown technique(s): nope" in capsys.readouterr().err


def test_listing(capsys):
    assert cli.main(["techniques"]) == 0
    out = capsys.readouterr().out
    assert all(t.id in out for t in TECHNIQUES) and f"{len(TECHNIQUES)} techniques (9 core)" in out
    cli.main(["techniques", "--suite", "core"])
    assert "9 techniques (9 core)" in capsys.readouterr().out
