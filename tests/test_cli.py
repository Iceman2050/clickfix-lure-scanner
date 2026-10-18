"""CLI end-to-end tests: exit-code contract + named-rule output."""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from clickfix_scanner.__main__ import main
from fixture_texts import MALICIOUS, BENIGN


def write_fixture(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_cli_malicious_exits_1_with_named_rules(tmp_path, capsys):
    path = write_fixture(tmp_path, "m1.txt", MALICIOUS["M1"])
    rc = main(["--text", path])
    out = capsys.readouterr().out
    assert rc == 1, f"malicious fixture must exit 1, got {rc}"
    assert "HIGH" in out
    assert "[fake-captcha]" in out
    assert "[winr-instruction]" in out
    assert "[run-dialog-paste]" in out
    assert "risk 75/100" in out


def test_cli_benign_exits_0(tmp_path, capsys):
    path = write_fixture(tmp_path, "b2.txt", BENIGN["B2"])
    rc = main(["--text", path])
    out = capsys.readouterr().out
    assert rc == 0, f"benign control must exit 0, got {rc}"
    assert "LOW" in out
    assert "no lure patterns detected" in out


def test_cli_missing_file_exits_2(capsys):
    rc = main(["--text", "/nonexistent/fixture.txt"])
    err = capsys.readouterr().err
    assert rc == 2, f"input error must exit 2, got {rc}"
    assert "error:" in err


def test_cli_stdin_path(tmp_path, capsys):
    # --text pointing at a benign file still exercises the file branch;
    # the mutually-exclusive group is covered by argparse itself.
    path = write_fixture(tmp_path, "m2.txt", MALICIOUS["M2"])
    rc = main(["--text", path])
    out = capsys.readouterr().out
    assert rc == 1
    assert "[powershell-encoded]" in out


def test_cli_all_malicious_exit_1(tmp_path):
    for fid, text in MALICIOUS.items():
        path = write_fixture(tmp_path, f"{fid}.txt", text)
        assert main(["--text", path]) == 1, f"{fid} must exit 1"


def test_cli_all_benign_exit_0(tmp_path):
    for fid, text in BENIGN.items():
        path = write_fixture(tmp_path, f"{fid}.txt", text)
        assert main(["--text", path]) == 0, f"{fid} must exit 0"
