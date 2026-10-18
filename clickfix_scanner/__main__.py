"""CLI: python -m clickfix_scanner --text FILE | --url URL | (stdin)

Exit codes: 0 = LOW/MEDIUM risk, 1 = HIGH risk, 2 = input error.
"""

import argparse
import sys
import urllib.request

from .rules import scan, HIGH_RISK_THRESHOLD


def _read_input(args):
    if args.url:
        req = urllib.request.Request(args.url,
                                     headers={"User-Agent": "clickfix-lure-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")
    if args.text:
        with open(args.text, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    data = sys.stdin.read()
    if not data.strip():
        raise ValueError("no input: pass --text FILE, --url URL, or pipe page text on stdin")
    return data


def build_parser():
    parser = argparse.ArgumentParser(
        description="clickfix-lure-scanner: pre-click verdict on ClickFix lures")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--text", metavar="FILE",
                       help="file containing pasted page text / install command")
    group.add_argument("--url", help="URL to fetch and scan (page text only)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        text = _read_input(args)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    score, verdict, matched = scan(text)
    print("clickfix-lure-scanner verdict: %s (risk %d/100)" % (verdict, score))
    print("threshold for HIGH: >= %d" % HIGH_RISK_THRESHOLD)
    if matched:
        print("\nmatched rules:")
        for m in matched:
            print("  [%s] +%d — %s" % (m["rule"], m["weight"], m["evidence"]))
            print("          -> %s" % m["advice"])
    else:
        print("\nno lure patterns detected.")
    if verdict == "HIGH":
        print("\nDO NOT follow these instructions. Close the page.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
