"""Deterministic ClickFix lure detection rules.

Each rule is a named, testable function over pasted page text / a command.
No ML, no network, no heuristics that learn: the same input always yields
the same verdict. Rules return (matched: bool, evidence: str).
"""

import re

# ---------------------------------------------------------------------------
# individual rule detectors (pure functions, unit-testable)
# ---------------------------------------------------------------------------

def _re(pattern, text):
    return re.search(pattern, text, re.IGNORECASE | re.DOTALL)


def detect_fake_captcha(text):
    """Fake human-verification page that funnels into clipboard/Run steps."""
    captcha = _re(r"(i'?m not a robot|verify you are (a )?human|"
                  r"complete the (captcha |verification )?step|"
                  r"press\s*(&|and)\s*hold|click (the )?(checkbox|allow))",
                  text)
    funnel = _re(r"(clipboard|copy (this|the) (command|text|code)|"
                 r"paste (it|the (command|text))|win\s*\+\s*r|windows\s*\+\s*r|"
                 r"run dialog)", text)
    if captcha and funnel:
        return True, "fake verification language combined with clipboard/Run instructions"
    return False, ""


def detect_winr_instruction(text):
    """Explicit 'press Win+R' style instructions."""
    if _re(r"(win(dows)?\s*(\+|key)\s*r\b|⊞\s*\+\s*r|windows key.*\br\b|"
           r"press r .*windows|run dialog|run window|type .* in (the )?run)",
           text):
        return True, "instructs the victim to open the Windows Run dialog (Win+R)"
    return False, ""


def detect_run_dialog_paste(text):
    """Paste-into-Run-dialog step (the ClickFix payload delivery)."""
    paste = _re(r"\bpaste\b", text)
    run = _re(r"(run (dialog|window|box)|press enter|hit enter|click ok)", text)
    if paste and run:
        return True, "tells the victim to paste something into Run and execute it"
    return False, ""


def detect_clipboard_swap(text):
    """The 'Deception' trick: a Copy button whose clipboard payload differs
    from the visible text (Push Security, Oct 2026). Static heuristics."""
    mismatch_lang = _re(r"(copied to clipboard is different|"
                        r"the (copied|clipboard) (text|command) (is )?different|"
                        r"what you (see|read) is not what (gets|is) copied|"
                        r"clipboard (hijack|swap|substitut))", text)
    hidden_payload = _re(r"(data-clipboard-text|navigator\.clipboard\.writeText|"
                          r"execCommand\(['\"]copy['\"]\))", text)
    encoded_blob = _re(r"[A-Za-z0-9+/]{120,}={0,2}", text)  # long base64 blob
    copy_button = _re(r"\bcopy\b", text)
    if mismatch_lang:
        return True, "page describes a copy button whose clipboard content differs from visible text"
    if hidden_payload and copy_button:
        return True, "page contains a programmatic clipboard-write behind a Copy button"
    if encoded_blob and copy_button and _re(r"(install|run|paste)", text):
        return True, "Copy-adjacent long encoded blob suggests a swapped clipboard payload"
    return False, ""


def detect_mshta(text):
    if _re(r"\bmshta(\.exe)?\b", text):
        return True, "uses mshta.exe, a classic LOLBin for executing remote payloads"
    return False, ""


def detect_powershell_encoded(text):
    ps = _re(r"powershell(\.exe)?", text)
    encoded = _re(r"(-EncodedCommand|-enc\b|FromBase64String|"
                  r"-e[nc]\s+[A-Za-z0-9+/=]{40,}|IEX|Invoke-Expression)", text)
    if ps and encoded:
        return True, "PowerShell with encoded/obfuscated command — hides the real payload"
    return False, ""


def detect_redirect_cloaking(text):
    """Trusted-domain redirect abused to cloak the real destination
    (e.g. bing.com/ck/a links in Google ads -> fake installer)."""
    official = ("anthropic.com", "claude.ai")
    bing_ck = _re(r"bing\.com/ck/a", text)
    generic_redirect = _re(r"(google(adservices|\.com/url)|t\.co|bit\.ly|tinyurl)\S*",
                           text)
    download = _re(r"(download|installer|\.exe|\.msi)", text)
    if bing_ck and download:
        return True, "bing.com redirect link paired with a download — the Oct 2026 'Deception' pattern"
    if generic_redirect and download and _re(r"\bad\b", text):
        return True, "ad/shortened redirect link leading to a download"
    # anchor-text vs href mismatch: [Download from official site](http://evil...)
    mismatches = re.findall(
        r"\[([^\]]{5,80})\]\((https?://[^)\s]+)\)", text)
    for label, href in mismatches:
        label_l = label.lower()
        host = re.sub(r"^https?://", "", href).split("/")[0].lower()
        if ("claude" in label_l or "anthropic" in label_l) \
                and not any(host == o or host.endswith("." + o) for o in official):
            return True, "link labeled '%s' actually points to %s" % (label.strip(), host)
    return False, ""


def detect_device_code_phish(text):
    if _re(r"(microsoft\.com/devicelogin|aka\.ms/devicelogin)", text) and \
            _re(r"(enter (this|the|your) code|device code|sign in.*code|"
                r"go to .* and enter)", text):
        return True, "device-code phishing: victim is walked to a Microsoft device-login page to enter an attacker code"
    return False, ""


def detect_typosquat_brand_claude(text):
    """Brand-abuse domains around 'claude'/'anthropic' that are not official."""
    official = ("anthropic.com", "claude.ai")
    candidates = re.findall(r"https?://([A-Za-z0-9.-]+)", text)
    candidates += re.findall(r"\b([A-Za-z0-9-]*claude[A-Za-z0-9-]*\.[a-z]{2,})\b",
                             text, re.IGNORECASE)
    candidates += re.findall(r"\b([A-Za-z0-9-]*anthropic[A-Za-z0-9-]*\.[a-z]{2,})\b",
                             text, re.IGNORECASE)
    for host in {c.lower().strip(".") for c in candidates}:
        if "claude" in host or "anthropic" in host:
            if not any(host == o or host.endswith("." + o) for o in official):
                return True, "brand-abuse domain '%s' impersonating Claude/Anthropic" % host
    return False, ""


def detect_fake_verification_challenge(text):
    """'Verifying your browser / press & hold / turnstile-lookalike' pages."""
    if _re(r"(verifying you are human|verifying your browser|"
           r"checking your browser|cloudflare.*verify|press (&|and) hold|"
           r"hold the button|complete (the )?challenge)", text) and \
            _re(r"(clipboard|copy|paste|run|powershell|cmd)", text):
        return True, "fake browser-verification challenge used as cover for clipboard/Run steps"
    return False, ""


# ---------------------------------------------------------------------------
# rule registry: id -> (weight, detector, plain-language advice)
# ---------------------------------------------------------------------------

RULES = [
    ("fake-captcha", 25, detect_fake_captcha,
     "This looks like a fake CAPTCHA page. Real CAPTCHAs never ask you to copy "
     "text, open the Run dialog, or paste commands."),
    ("winr-instruction", 30, detect_winr_instruction,
     "It tells you to press Win+R. No legitimate website or installer needs you "
     "to open the Windows Run dialog."),
    ("run-dialog-paste", 20, detect_run_dialog_paste,
     "Pasting something into the Run dialog and pressing Enter executes it "
     "immediately — this is how the malware gets installed."),
    ("clipboard-swap", 25, detect_clipboard_swap,
     "The Copy button may place a DIFFERENT command on your clipboard than the "
     "text you see. Always paste into Notepad first and read it."),
    ("mshta", 30, detect_mshta,
     "It invokes mshta.exe — a Windows tool attackers abuse to run remote code. "
     "Legitimate installers do not use it."),
    ("powershell-encoded", 30, detect_powershell_encoded,
     "It runs an encoded/obfuscated PowerShell command. Encoding is used to "
     "hide what the command really does from you and from scanners."),
    ("redirect-cloaking", 20, detect_redirect_cloaking,
     "The link hides behind a trusted domain (e.g. bing.com) so it looks safe "
     "in an ad, but the real destination is different."),
    ("device-code-phish", 30, detect_device_code_phish,
     "It walks you through entering a code on a Microsoft login page. That "
     "code links YOUR account to the attacker's session."),
    ("typosquat-brand-claude", 20, detect_typosquat_brand_claude,
     "The domain uses the Claude/Anthropic name but is not an official domain "
     "(anthropic.com / claude.ai)."),
    ("fake-verification-challenge", 15, detect_fake_verification_challenge,
     "A fake 'verifying your browser' screen is being used as cover for the "
     "clipboard/Run steps."),
]

HIGH_RISK_THRESHOLD = 60


def scan(text):
    """Run all rules. Returns (score, matched_rules, explanations)."""
    matched = []
    for rule_id, weight, detector, advice in RULES:
        hit, evidence = detector(text)
        if hit:
            matched.append({"rule": rule_id, "weight": weight,
                            "evidence": evidence, "advice": advice})
    score = min(100, sum(m["weight"] for m in matched))
    verdict = "HIGH" if score >= HIGH_RISK_THRESHOLD else \
              "MEDIUM" if score >= 30 else "LOW"
    return score, verdict, matched
