"""phish-forge CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scoring import analyze
from .stix import to_stix_json

def _analyze_one(path: Path, as_json: bool, as_stix: bool = False) -> int:
    report = analyze(path)
    if as_json:
        print(report.to_json())
        return 0
    if as_stix:
        print(to_stix_json(report))
        return 0

    verdict = report.verdict.value.upper()
    print(f"phish-forge verdict: {verdict}  (score {report.score}/100)\n")

    if report.header_signals:
        print("  Headers")
        for s in report.header_signals:
            print(f"    ! {s.name:<28} {s.detail}")
        print()

    if report.urls:
        print(f"  URLs ({len(report.urls)} found)")
        for u in report.urls:
            marker = "!" if u.score > 0 else "-"
            sig_summary = ", ".join(s.name for s in u.signals) or "no flags"
            print(f"    {marker} {u.url}    {sig_summary}")
        print()

    if report.body_signals:
        print("  Body heuristics")
        for s in report.body_signals:
            print(f"    ! {s.name:<28} {s.detail!r}")
        print()

    confidence = "high" if report.score >= 70 else ("moderate" if report.score >= 40 else "low")
    print(f"  Verdict: {verdict} — {confidence} confidence")
    return 0 if report.verdict.value == "benign" else 1

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phish-forge",
        description="Analyze .eml files for phishing indicators.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze a single .eml file.")
    a.add_argument("path", type=Path)
    fmt = a.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    fmt.add_argument("--stix", action="store_true", help="Print flagged indicators as a STIX 2.1 bundle.")

    s = sub.add_parser("serve", help="Run the FastAPI service.")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)

    if args.command == "analyze":
        return _analyze_one(args.path.resolve(), args.json, args.stix)

    if args.command == "serve":
        try:
            import uvicorn
            from .api import app
        except ImportError:
            print("phish-forge: install the api extras: pip install 'phish-forge[api]'", file=sys.stderr)
            return 2
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 1

if __name__ == "__main__":
    sys.exit(main())
