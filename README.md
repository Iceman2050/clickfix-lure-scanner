# clickfix-lure-scanner

**Deterministic pre-click verdict on ClickFix lures.** Paste the page text (or hand it a URL) and get a named-rule risk score before anyone presses Win+R. Rule-based, no ML, no SOC tooling needed — 10 named rules, weighted scoring, exit codes your scripts can use.

## The news hook

**2026-10-09 — the "Deception" campaign:** Push Security (reported by BleepingComputer via SC World) documented attackers buying **Google ads whose visible destination was trusted bing.com** — `bing.com/ck/a` redirect links — that led victims to **fake Claude installer pages**. The pages used the new "Deception" trick: a Copy button whose **clipboard payload was swapped** to differ from the visible text, feeding victims a malicious command disguised as a verification step.

Source:
- https://www.scworld.com/brief/hackers-use-bing-redirects-in-google-ads-for-fake-claude-installers

This scanner exists for exactly that pattern: bing-redirect cloaking, clipboard-swap copy buttons, Win+R/Run-dialog instructions, and typosquat brand domains around Claude/Anthropic — all detected statically, before the click.

## How to run

```bash
# paste page text on stdin
echo "Press Win+R, paste the command and press Enter" | python -m clickfix_scanner

# or scan a saved page
python -m clickfix_scanner --text suspicious-page.txt

# or fetch a URL first (page text only, no execution)
python -m clickfix_scanner --url https://example.com/suspicious
```

Exit codes: `0` = LOW/MEDIUM risk, `1` = HIGH risk, `2` = input error.

Example output:

```
clickfix-lure-scanner verdict: HIGH (risk 75/100)
threshold for HIGH: >= 60

matched rules:
  [fake-captcha] +25 — fake verification language combined with clipboard/Run instructions
          -> This looks like a fake CAPTCHA page. Real CAPTCHAs never ask you to copy text, open the Run dialog, or paste commands.
  [winr-instruction] +30 — instructs the victim to open the Windows Run dialog (Win+R)
          -> It tells you to press Win+R. No legitimate website or installer needs you to open the Windows Run dialog.
  [run-dialog-paste] +20 — tells the victim to paste something into Run and execute it
          -> Pasting something into the Run dialog and pressing Enter executes it immediately — this is how the malware gets installed.

DO NOT follow these instructions. Close the page.
```

## The 10 rules

| Rule | Weight | What it catches |
|---|---|---|
| `fake-captcha` | 25 | Fake human-verification page funneling into clipboard/Run steps |
| `winr-instruction` | 30 | Explicit "press Win+R" instructions |
| `run-dialog-paste` | 20 | Paste-into-Run-dialog step (the ClickFix payload delivery) |
| `clipboard-swap` | 25 | Copy button whose clipboard payload differs from visible text ("Deception") |
| `mshta` | 30 | `mshta.exe` LOLBin invocation |
| `powershell-encoded` | 30 | PowerShell with encoded/obfuscated command |
| `redirect-cloaking` | 20 | Trusted-domain redirect (e.g. bing.com/ck/a) hiding the real destination |
| `device-code-phish` | 30 | Victim walked to a Microsoft device-login page to enter an attacker code |
| `typosquat-brand-claude` | 20 | Brand-abuse domains impersonating Claude/Anthropic |
| `fake-verification-challenge` | 15 | "Verifying your browser / press & hold" cover for clipboard/Run steps |

Score = sum of matched weights, capped at 100. HIGH ≥ 60, MEDIUM ≥ 30, else LOW.

## Tests

```bash
pip install pytest
python -m pytest -v   # 17 tests: 13 fixtures (9 malicious incl. 2 redacted/inert
                      # JSON fixtures + 4 benign controls), all 10 rules,
                      # scoring/exit-code behavior
```

## What it does NOT do

- It is a **static text heuristic, not a verdict on safety**: rules are keyword/regex patterns — a cleverly reworded lure can slip past, and unusual-but-legitimate admin docs can trip a rule. Always treat HIGH as "investigate", not proof.
- It does **not execute, fetch payloads, or detonate anything** — and it cannot tell you what a payload does. The `--url` fetch downloads page text only.
- It does **not inspect the actual clipboard** or compare what a live Copy button puts on it — the clipboard-swap rule detects the *markers* of the trick (hidden clipboard-write code, mismatch language), not a live swap.
- It knows **nothing about URLs beyond pattern matching** — no reputation lookup, no DNS, no WHOIS, no live blocklist check.
- Non-English lures are largely invisible to it — every rule is English-pattern based.
- The test fixtures in `tests/` are **synthetic and inert** (the two JSON fixtures carry keyword tokens only, `"inert": true`); they exist to prove the rules fire, not to model real payloads.

## Built by Ingenious AI

Part of the Ingenious AI security ecosystem:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

## License

MIT — see [LICENSE](LICENSE).
