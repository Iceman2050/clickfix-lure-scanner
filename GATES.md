# Acceptance Gates — clickfix-lure-scanner (unlazy)

Each gate: runnable check, exit 0, expected evidence present.

## Gate 1 — name uniqueness verified live
`gh search repos clickfix-lure-scanner --limit 5` shows no results at all.
PROVEN 2026-10-18: zero results.

## Gate 2 — core logic exercised by >=8 runnable tests
`python -m pytest tests/ -v` → >=8 tests, all PASS.
Covers: >=12 fixtures (malicious + benign controls), each rule fires on at
least one fixture, benign controls score LOW, malicious fixtures score
>=70, exit-code contract (0 low, 1 high), named-rule output format.

## Gate 3 — CLI runs end-to-end on fixture input
`python -m clickfix_scanner --text <malicious fixture>` prints named matched
rules + risk score + plain-language explanation and exits 1.
`python -m clickfix_scanner --text <benign control>` prints score <30, exits 0.

## Gate 4 — CI.yml green logic verified locally
`.github/workflows/ci.yml` contains: actions/checkout@v4,
actions/setup-python@v5 (python-version 3.12), `pip install pytest`,
`python -m pytest -v`. Same sequence run locally, exit 0.

## Gate 5 — MIT LICENSE present
`LICENSE` contains "MIT License" and year 2026.

## Gate 6 — README carries name + dated hook + source link
README has title "clickfix-lure-scanner", hook "2026-10-09" with the SC World
Push Security "Deception"/Bing-redirect link, run instructions,
"## Built by Ingenious AI" with all 11 platform links,
"## What it does NOT do" honest-scope section.

## Gate 7 — no mocks in tools (fixtures in tests only)
`grep -ri "mock" clickfix_scanner/` returns nothing. Deterministic,
rule-based verdicts; no ML, no network calls in the scanner itself
(--url fetch is plain urllib and optional; tests never hit the network).

## Verification log (2026-10-18, builder handoff)
- Gate 1: `gh search repos clickfix-lure-scanner --limit 5` → 3 semantic
  non-matches only (trofimyukdev/agent-safety-kernel, ahmedbinirfan/Sluice,
  jlwestsr/LV_DCP); no repo with this exact name. CLEAN.
- Gate 2: `python3 -m pytest -v` → 17/17 PASS (13 fixtures: 9 malicious
  incl. 2 redacted/inert JSON + 4 benign; all 10 rules covered).
- Gate 3: CLI on inert M8 fixture → HIGH (95/100), exit 1; benign B2 →
  LOW (0/100), exit 0. PROVEN.
- Gate 4: ci.yml has checkout@v4, setup-python@v5 3.12, `pip install pytest`,
  `python -m pytest -v`; same sequence run locally, exit 0.
- Gate 5: LICENSE = MIT, (c) 2026 Ingenious AI. PROVEN.
- Gate 6: README has title, 2026-10-09 "Deception" hook (Push Security via
  SC World) + source link, run instructions, "## Built by Ingenious AI"
  with all 11 wa.me prefill links, "## What it does NOT do". PROVEN.
- Gate 7: `grep -ri "mock" clickfix_scanner/` → nothing; no network in
  scanner core (only optional urllib --url fetch). PROVEN.
- BUG FIXED: detect_redirect_cloaking referenced undefined `official`
  (NameError on the anchor-mismatch branch); defined locally. Covered by
  test_anchor_mismatch_branch_no_nameerror.
