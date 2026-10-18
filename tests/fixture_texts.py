"""Test fixtures for clickfix-lure-scanner.

13 fixtures: 9 malicious lure texts (M1-M9, including 2 explicitly
REDACTED/INERT JSON fixtures) + 4 benign controls (B1-B4).

The fixtures are synthetic test inputs for a DEFENSIVE detector — like AV
signature test files. The two JSON fixtures (M7, M8) carry keyword-only
tokens with no command bodies and no executable payloads ("inert": true).
All other malicious fixtures are short lure-text descriptions with every
payload redacted; none of them contain anything that runs.
"""

MALICIOUS = {
    "M1": (
        "Complete the verification step to prove you are human. "
        "I'm not a robot \u2014 check the box below. "
        "STEP 1: Press Win+R. "
        "STEP 2: Copy this command, paste it into the Run dialog, and press Enter."
    ),
    "M2": (
        "STEP 1: Press Win+R to open the Run dialog. "
        "STEP 2: Copy the line below, paste it, and press Enter. "
        "powershell.exe -EncodedCommand "
        "[PAYLOAD REDACTED \u2014 inert test fixture, no command included]."
    ),
    "M3": (
        "Sponsored result. Download the free installer (setup.exe) from "
        "https://bing.com/ck/a?u=[REDACTED]. After the download finishes: "
        "click Copy, press Win+R, paste into the Run dialog, and press Enter. "
        "The page runs the file via mshta [COMMAND REDACTED]."
    ),
    "M4": (
        "Google ad: 'Claude AI \u2014 Official Download'. The ad destination shows "
        "https://bing.com/ck/a?u=[REDACTED] but leads to a download of "
        "ClaudeInstaller.exe. Get it from "
        "[Download Claude Installer](https://claude-desktop-download.net/setup.exe). "
        "The page's Copy button hides its real content: the copied command is "
        "different from the visible text. Then press Win+R, paste into the Run "
        "dialog, and press Enter."
    ),
    "M5": (
        "Sponsored ad. Verify your device to continue: go to "
        "microsoft.com/devicelogin and enter this device code [CODE REDACTED]. "
        "Then download the security update via bit.ly/[REDACTED]. "
        "Final step: press Win+R, paste the text into the Run dialog, and press Enter."
    ),
    "M6": (
        "Verifying you are human. Checking your browser before you continue... "
        "Press and hold the button below to complete the challenge. "
        "Then copy the verification command to your clipboard and paste it into "
        "Run, and press Enter. Note: the page's Copy button uses "
        "data-clipboard-text=[REDACTED], so the copied command is different "
        "from the visible text."
    ),
    "M9": (
        "STEP 1: Complete the verification \u2014 I'm not a robot, press and hold "
        "to verify you are human. "
        "STEP 2: Press Win+R to open the Run dialog. "
        "STEP 3: Copy the text below and paste it into the Run dialog, then "
        "press Enter. Note: the copied command is different from the visible text."
    ),
}

BENIGN = {
    "B1": (
        "Welcome! To create an account, check the 'I'm not a robot' checkbox "
        "and select all images with bicycles. If the images are unclear, click "
        "the refresh icon. Need help? Contact support."
    ),
    "B2": (
        "Download the official Claude desktop app from claude.ai/download. "
        "Installers are available for Windows and macOS, signed by Anthropic. "
        "Check the release notes for version history."
    ),
    "B3": (
        "Keyboard shortcuts cheat sheet: press Ctrl+C to copy selected text, "
        "Ctrl+V to paste it into your document. Press the Windows key to open "
        "the Start menu, or Alt+Tab to switch apps."
    ),
    "B4": (
        "To reset your password, visit account.microsoft.com/security and "
        "follow the on-screen steps. Microsoft will never call you to ask for "
        "verification codes. If someone asks, hang up."
    ),
}
