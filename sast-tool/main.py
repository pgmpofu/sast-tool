#!/usr/bin/env python3
"""
SAST Tool — Static Application Security Testing
Language-agnostic security scanner for source code.

Usage:
    python -m sast_tool <target> [options]
    docker run --rm -v $(pwd):/src sast-tool /src [options]
"""

import sys
import argparse
import os
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        prog="sast-tool",
        description="🔍 SAST Tool — Static Application Security Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory, print to terminal
  sast-tool ./myproject

  # Output JSON report
  sast-tool ./myproject --format json --output report.json

  # Output HTML report
  sast-tool ./myproject --format html --output report.html

  # All three outputs
  sast-tool ./myproject --format all --output ./reports/

  # Filter by severity
  sast-tool ./myproject --severity CRITICAL HIGH

  # Verbose with remediation details
  sast-tool ./myproject --verbose

  # Use custom rules directory
  sast-tool ./myproject --rules ./my-custom-rules/
        """
    )

    parser.add_argument(
        "target",
        help="File or directory to scan"
    )

    parser.add_argument(
        "--format", "-f",
        choices=["terminal", "json", "html", "all"],
        default="terminal",
        help="Output format (default: terminal)"
    )

    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path or directory (for json/html/all). Defaults to ./sast-report.[ext]"
    )

    parser.add_argument(
        "--severity", "-s",
        nargs="+",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Filter findings by severity level(s)"
    )

    parser.add_argument(
        "--category", "-c",
        nargs="+",
        default=None,
        help="Filter findings by category (e.g. INJECTION SECRETS CRYPTOGRAPHY)"
    )

    parser.add_argument(
        "--rules", "-r",
        default=None,
        help="Path to custom rules directory"
    )

    parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Regex patterns for paths to exclude (e.g. tests/ migrations/)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show remediation advice and full metadata"
    )

    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "none"],
        default="HIGH",
        help="Exit with code 1 if findings at or above this severity exist (default: HIGH). Use 'none' to always exit 0."
    )

    parser.add_argument(
        "--version",
        action="version",
        version="sast-tool 1.0.0"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Lazy import to keep startup fast
    from sast.scanner import Scanner
    from sast.formatters import print_terminal, write_json, write_html

    target = Path(args.target)
    if not target.exists():
        print(f"❌ Error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(2)

    scanner = Scanner(
        rules_path=args.rules,
        severity_filter=args.severity,
        category_filter=args.category,
        exclude_paths=args.exclude,
    )

    result = scanner.scan(str(target))

    fmt = args.format
    output = args.output

    # Determine output paths
    if fmt == "all":
        out_dir = Path(output) if output else Path("./sast-reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"report-{result.scan_id}.json"
        html_path = out_dir / f"report-{result.scan_id}.html"
    elif fmt == "json":
        json_path = Path(output) if output else Path(f"sast-report-{result.scan_id}.json")
    elif fmt == "html":
        html_path = Path(output) if output else Path(f"sast-report-{result.scan_id}.html")

    # Always print terminal summary
    print_terminal(result, verbose=args.verbose)

    if fmt in ("json", "all"):
        path = write_json(result, str(json_path))
        print(f"📄 JSON report: {path}")

    if fmt in ("html", "all"):
        path = write_html(result, str(html_path))
        print(f"🌐 HTML report: {path}")

    # Exit code for CI/CD integration
    if args.fail_on != "none":
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        threshold = severity_order[args.fail_on]
        for finding in result.findings:
            if severity_order.get(finding.severity, 99) <= threshold:
                sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
