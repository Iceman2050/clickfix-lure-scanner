"""Rule-level tests for clickfix-lure-scanner.

13 fixtures total: 9 malicious (M1-M9, incl. 2 redacted/inert JSON fixtures)
+ 4 benign controls (B1-B4). Covers all 10 named rules.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from clickfix_scanner import rules
from clickfix_scanner.rules import scan
from fixture_texts import MALICIOUS, BENIGN

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures"


def load_inert_fixtures():
    """Return [(fixture_id, text)] for the redacted/inert JSON fixtures."""
    out = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["inert"] is True, f"{path.name} must be marked inert"
        assert data["pattern_markers"], f"{path.name} must list pattern markers"
        out.append((data["fixture_id"], data["text"]))
    return out


INERT = load_inert_fixtures()
ALL_MALICIOUS = list(MALICIOUS.items()) + INERT


# ---------------------------------------------------------------------------
# 1. every one of the 10 named rules fires on its targeted fixture
# ---------------------------------------------------------------------------

RULE_TARGETS = [
    ("fake-captcha", rules.detect_fake_captcha, "M1"),
    ("winr-instruction", rules.detect_winr_instruction, "M1"),
    ("run-dialog-paste", rules.detect_run_dialog_paste, "M1"),
    ("clipboard-swap", rules.detect_clipboard_swap, "M4"),
    ("mshta", rules.detect_mshta, "M3"),
    ("powershell-encoded", rules.detect_powershell_encoded, "M2"),
    ("redirect-cloaking", rules.detect_redirect_cloaking, "M3"),
    ("device-code-phish", rules.detect_device_code_phish, "M5"),
    ("typosquat-brand-claude", rules.detect_typosquat_brand_claude, "M4"),
    ("fake-verification-challenge", rules.detect_fake_verification_challenge, "M6"),
]


def test_every_rule_fires_on_its_target_fixture():
    assert len(RULE_TARGETS) == 10, "all 10 rules must be covered"
    for rule_id, detector, fixture_id in RULE_TARGETS:
        hit, evidence = detector(MALICIOUS[fixture_id])
        assert hit, f"rule {rule_id} did not fire on fixture {fixture_id}"
        assert evidence, f"rule {rule_id} fired without evidence"


# ---------------------------------------------------------------------------
# 2. all malicious fixtures score HIGH (>=60); benign controls score LOW
# ---------------------------------------------------------------------------

def test_all_malicious_fixtures_score_high():
    assert len(ALL_MALICIOUS) == 9, "expected 9 malicious fixtures"
    for fid, text in ALL_MALICIOUS:
        score, verdict, matched = scan(text)
        assert verdict == "HIGH", f"{fid}: verdict={verdict} score={score}"
        assert score >= 60, f"{fid}: score {score} below HIGH threshold"
        assert matched, f"{fid}: HIGH verdict with no matched rules"


def test_benign_controls_score_low():
    assert len(BENIGN) == 4, "expected 4 benign controls"
    for fid, text in BENIGN.items():
        score, verdict, matched = scan(text)
        assert verdict == "LOW", f"{fid}: verdict={verdict} score={score}"
        assert score < 30, f"{fid}: benign score {score} too high"
        assert matched == [], f"{fid}: benign control matched rules: {matched}"


# ---------------------------------------------------------------------------
# 3. rule attribution is precise on key fixtures
# ---------------------------------------------------------------------------

def test_m1_rule_attribution():
    score, verdict, matched = scan(MALICIOUS["M1"])
    ids = {m["rule"] for m in matched}
    assert ids == {"fake-captcha", "winr-instruction", "run-dialog-paste"}
    assert score == 25 + 30 + 20 == 75


def test_m7_inert_fixture_rule_attribution():
    fid, text = next(t for t in INERT if t[0] == "M7-inert-powershell")
    score, verdict, matched = scan(text)
    ids = {m["rule"] for m in matched}
    assert ids == {"mshta", "powershell-encoded", "winr-instruction",
                   "run-dialog-paste"}
    assert verdict == "HIGH"


def test_m8_inert_deception_fixture_rule_attribution():
    fid, text = next(t for t in INERT if t[0] == "M8-inert-deception")
    score, verdict, matched = scan(text)
    ids = {m["rule"] for m in matched}
    assert "redirect-cloaking" in ids
    assert "clipboard-swap" in ids
    assert verdict == "HIGH"


# ---------------------------------------------------------------------------
# 4. scoring mechanics: cap, bands, determinism
# ---------------------------------------------------------------------------

def test_scoring_caps_at_100():
    mega = "\n".join(t for _, t in ALL_MALICIOUS)
    score, verdict, matched = scan(mega)
    raw = sum(m["weight"] for m in matched)
    assert raw > 100, "mega-fixture must exceed the cap to prove it"
    assert score == 100
    assert verdict == "HIGH"


def test_verdict_bands():
    score, verdict, _ = scan("")
    assert score == 0 and verdict == "LOW"
    score, verdict, _ = scan(MALICIOUS["M6"])  # 85
    assert verdict == "HIGH"


def test_scan_is_deterministic():
    for fid, text in ALL_MALICIOUS:
        assert scan(text) == scan(text), f"{fid}: non-deterministic scan"


# ---------------------------------------------------------------------------
# 5. matched-rule output format (named rules, weights, evidence, advice)
# ---------------------------------------------------------------------------

def test_named_rule_output_format():
    _, _, matched = scan(MALICIOUS["M1"])
    registered = {r[0] for r in rules.RULES}
    for m in matched:
        assert set(m) == {"rule", "weight", "evidence", "advice"}
        assert m["rule"] in registered, f"unknown rule id {m['rule']}"
        assert isinstance(m["weight"], int) and m["weight"] > 0
        assert m["evidence"] and m["advice"]


# ---------------------------------------------------------------------------
# 6. redirect-cloaking anchor-mismatch branch must not crash
#    (regression: `official` was referenced but undefined in that function)
# ---------------------------------------------------------------------------

def test_anchor_mismatch_branch_no_nameerror():
    official_link = "[Download Claude Installer](https://claude.ai/download)"
    hit, _ = rules.detect_redirect_cloaking(official_link)
    assert hit is False  # official domain: no mismatch, no crash
    evil_link = "[Download Claude Installer](https://claude-setup-free.net/x.exe)"
    hit, evidence = rules.detect_redirect_cloaking(evil_link)
    assert hit is True
    assert "claude-setup-free.net" in evidence
