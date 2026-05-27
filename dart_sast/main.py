#!/usr/bin/env python3
"""
dart_sast/__main__.py — CLI entry point
Run as: python -m dart_sast <target>
"""

import sys
import json
import argparse
import textwrap
from pathlib import Path
from datetime import datetime

from .analyzer import (
    analyze_directory, analyze_file, load_rules_from_dir,
    AnalysisResult, Severity,
)
from .reporter import render_html, render_sarif, render_defectdojo


SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[34m",
    Severity.INFO:     "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
SEV_ORDER = {s: i for i, s in enumerate(Severity)}


def _sev_badge(sev: Severity, no_color: bool = False) -> str:
    if no_color:
        return f"[{sev.value}]"
    return f"{SEVERITY_COLOR[sev]}{BOLD}[{sev.value}]{RESET}"


def print_console(result: AnalysisResult, no_color: bool = False) -> None:
    if not result.findings:
        print(f"\n{'✅' if not no_color else ''} No findings. {result.files_scanned} file(s) scanned.\n")
        return
    print()
    for f in sorted(result.findings, key=lambda x: (SEV_ORDER[x.severity], x.file, x.line)):
        badge = _sev_badge(f.severity, no_color)
        tags  = f"  Tags     : {', '.join(f.tags)}" if f.tags else ""
        print(f"{badge} {BOLD}{f.rule_id}{RESET} — {f.title}")
        print(f"  📍 {f.file}:{f.line}:{f.column}")
        print(f"  {f.description.strip()}")
        print(f"  Snippet  : {f.snippet.strip()}")
        print(f"  Suggest  : {f.suggestion.strip()}")
        print(f"  CWE      : {f.cwe}")
        if f.owasp:
            print(f"  OWASP    : {f.owasp}")
        if tags:
            print(tags)
        print()

    counts = result.by_severity
    print("─" * 60)
    print(f"Files scanned : {result.files_scanned}")
    print(f"Total findings: {len(result.findings)}")
    for sev in Severity:
        if counts[sev]:
            print(f"  {_sev_badge(sev, no_color)} {counts[sev]}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dart_sast",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            ┌─────────────────────────────────────────┐
            │  dart_sast — SAST for Dart / Flutter     │
            └─────────────────────────────────────────┘
            Static analysis security testing for Dart/Flutter source code.
        """),
    )
    p.add_argument("target", help="File or directory to scan")
    p.add_argument(
        "--output", "-o",
        choices=["console", "json", "html", "sarif", "defectdojo"],
        default="console",
        help=(
            "Output format. 'defectdojo' emits Semgrep JSON schema, "
            "importable via DefectDojo → Findings → Import → Semgrep JSON Report"
        ),
    )
    p.add_argument("--out-file", "-f", metavar="FILE",
                   help="Write output to FILE instead of stdout")
    p.add_argument("--severity", "-s",
                   choices=[s.value for s in Severity],
                   default=None,
                   help="Minimum severity to report")
    p.add_argument("--rules-dir", "-r", metavar="DIR",
                   help="Path to custom YAML rules directory (overrides built-in rules)")
    p.add_argument("--exclude-dir", "-x", action="append", default=[], metavar="DIR",
                   help="Directory name to exclude (may repeat)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color output")
    p.add_argument("--list-rules", action="store_true",
                   help="List all loaded rules and exit")
    p.add_argument("--fail-on", choices=[s.value for s in Severity], default=None,
                   help="Exit code 1 if any finding meets this severity threshold")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    rules = load_rules_from_dir(args.rules_dir) if args.rules_dir else load_rules_from_dir()

    if args.list_rules:
        print(f"\n{'ID':<18} {'SEV':<10} {'CWE':<12} {'TAGS':<30} TITLE")
        print("─" * 90)
        for rule in rules:
            tags = ", ".join(rule.tags[:3])
            print(f"{rule.rule_id:<18} {rule.severity.value:<10} {rule.cwe:<12} {tags:<30} {rule.title}")
        print(f"\n{len(rules)} rules loaded.\n")
        sys.exit(0)

    target = Path(args.target)
    if not target.exists():
        print(f"Error: '{target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    default_excludes = [".dart_tool", "build", ".git", ".idea"]
    exclude_dirs = list(set(default_excludes + args.exclude_dir))

    if target.is_dir():
        result = analyze_directory(str(target), rules=rules, exclude_dirs=exclude_dirs)
    else:
        findings = analyze_file(str(target), rules=rules)
        result = AnalysisResult(files_scanned=1, findings=findings)

    # Severity filter
    if args.severity:
        min_order = SEV_ORDER[Severity(args.severity)]
        result.findings = [f for f in result.findings if SEV_ORDER[f.severity] <= min_order]

    # ── Render ────────────────────────────────────────────────────────────────
    if args.output == "console":
        print_console(result, no_color=args.no_color)

    elif args.output == "json":
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "files_scanned": result.files_scanned,
            "findings": [
                {
                    "rule_id":    f.rule_id,
                    "title":      f.title,
                    "severity":   f.severity.value,
                    "cwe":        f.cwe,
                    "owasp":      f.owasp,
                    "tags":       f.tags,
                    "file":       f.file,
                    "line":       f.line,
                    "column":     f.column,
                    "snippet":    f.snippet,
                    "suggestion": f.suggestion,
                }
                for f in result.findings
            ],
        }
        _write_or_print(json.dumps(data, indent=2), args.out_file)

    elif args.output == "html":
        html = render_html(result)
        dest = args.out_file or "dart_sast_report.html"
        Path(dest).write_text(html, encoding="utf-8")
        print(f"HTML report written to {dest}")

    elif args.output == "sarif":
        sarif = render_sarif(result)
        dest = args.out_file or "dart_sast_report.sarif"
        Path(dest).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        print(f"SARIF report written to {dest}")

    elif args.output == "defectdojo":
        dojo = render_defectdojo(result)
        dest = args.out_file or "dart_sast_defectdojo.json"
        Path(dest).write_text(json.dumps(dojo, indent=2), encoding="utf-8")
        print(f"DefectDojo (Semgrep JSON) report written to {dest}")
        print("Import in DefectDojo: Findings → Import → Scanner: 'Semgrep JSON Report'")

    # ── Exit code ─────────────────────────────────────────────────────────────
    if args.fail_on:
        threshold = SEV_ORDER[Severity(args.fail_on)]
        if any(SEV_ORDER[f.severity] <= threshold for f in result.findings):
            sys.exit(1)


def _write_or_print(content: str, out_file: str | None) -> None:
    if out_file:
        Path(out_file).write_text(content, encoding="utf-8")
        print(f"Report written to {out_file}")
    else:
        print(content)


if __name__ == "__main__":
    main()