"""Bulk-test the SigmaMatch engine against a directory of Sigma rules.

Usage:
    python -m app.tests.bulk_test <rules_directory>

Example:
    # Clone SigmaHQ rules first:
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git

    # Run bulk test against all rules:
    python -m app.tests.bulk_test sigma/rules

    # Or test a specific subfolder:
    python -m app.tests.bulk_test sigma/rules/windows/process_creation

The script performs three checks per rule:
  1. PARSE   — Can the rule YAML be parsed without errors?
  2. POSITIVE — Does a synthetically generated matching event produce a match?
  3. NEGATIVE — Does a non-matching synthetic event correctly return no match?

Results are printed live and a summary is saved to bulk_test_report.txt.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Ensure the backend package is importable when run from backend/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.core.log_generator import generate_negative_event, generate_positive_event
from app.core.matcher import match_events
from app.core.parser import parse_rule


@dataclass
class RuleResult:
    path: str
    title: str = ""
    parse_ok: bool = False
    parse_error: str = ""
    positive_match: bool | None = None  # None = skipped (parse failed)
    negative_clean: bool | None = None  # None = skipped
    notes: str = ""


@dataclass
class BulkReport:
    total: int = 0
    parse_ok: int = 0
    parse_fail: int = 0
    positive_pass: int = 0
    positive_fail: int = 0
    positive_skip: int = 0
    negative_pass: int = 0
    negative_fail: int = 0
    negative_skip: int = 0
    results: list[RuleResult] = field(default_factory=list)
    unsupported_conditions: list[str] = field(default_factory=list)


def _collect_rule_files(directory: str) -> list[Path]:
    """Recursively find all .yml / .yaml files."""
    root = Path(directory)
    if not root.is_dir():
        print(f"ERROR: '{directory}' is not a directory.")
        sys.exit(1)
    files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    # Exclude non-rule files (common SigmaHQ patterns)
    return [f for f in files if f.name not in ("sigma-schema.yml", "config.yml")]


def check_single_rule(path: Path) -> RuleResult:
    """Run all three checks on a single rule file."""
    result = RuleResult(path=str(path))
    yaml_text = path.read_text(encoding="utf-8", errors="replace")

    # 1. Parse test
    try:
        rule = parse_rule(yaml_text)
        result.parse_ok = True
        result.title = rule.title
    except (ValueError, Exception) as exc:
        result.parse_ok = False
        result.parse_error = str(exc)
        return result

    # Skip matching tests if there are no selections (e.g. correlation rules)
    if not rule.selections:
        result.notes = "No selections — skipped match tests"
        return result

    # 2. Positive match test
    try:
        pos_event = generate_positive_event(rule)
        pos_result = match_events(rule, [pos_event])
        result.positive_match = pos_result.matched
    except Exception as exc:
        result.positive_match = False
        result.notes = f"Positive test error: {exc}"

    # 3. Negative match test
    try:
        neg_event = generate_negative_event(rule)
        neg_result = match_events(rule, [neg_event])
        result.negative_clean = not neg_result.matched  # Should NOT match
    except Exception as exc:
        result.negative_clean = False
        result.notes += f" | Negative test error: {exc}"

    return result


def run_bulk_test(directory: str) -> BulkReport:
    """Run all tests and return a report."""
    files = _collect_rule_files(directory)
    report = BulkReport(total=len(files))

    print(f"\n{'='*70}")
    print(f"  Sigma Rule Bulk Test — {len(files)} rules found")
    print(f"  Source: {os.path.abspath(directory)}")
    print(f"{'='*70}\n")

    for i, path in enumerate(files, 1):
        r = check_single_rule(path)
        report.results.append(r)

        # Tally
        if r.parse_ok:
            report.parse_ok += 1
        else:
            report.parse_fail += 1

        if r.positive_match is True:
            report.positive_pass += 1
        elif r.positive_match is False:
            report.positive_fail += 1
        else:
            report.positive_skip += 1

        if r.negative_clean is True:
            report.negative_pass += 1
        elif r.negative_clean is False:
            report.negative_fail += 1
        else:
            report.negative_skip += 1

        # Live progress
        status = "OK" if r.parse_ok else "FAIL"
        pos_s = {True: "pos:PASS", False: "pos:FAIL", None: "pos:SKIP"}[r.positive_match]
        neg_s = {True: "neg:PASS", False: "neg:FAIL", None: "neg:SKIP"}[r.negative_clean]
        short = str(path.relative_to(Path(directory))) if path.is_relative_to(Path(directory)) else path.name

        # Print failures with details, successes as compact
        if not r.parse_ok:
            print(f"  [{i:>4}/{report.total}] PARSE FAIL  {short}")
            print(f"           Error: {r.parse_error[:120]}")
        elif r.positive_match is False or r.negative_clean is False:
            print(f"  [{i:>4}/{report.total}] {pos_s} {neg_s}  {short}")
            if r.notes:
                print(f"           Note: {r.notes[:120]}")
        else:
            # Compact success line — only print every 50th or on completion
            if i % 100 == 0 or i == report.total:
                print(f"  [{i:>4}/{report.total}] ... {report.parse_ok} parsed, {report.positive_pass} pos-pass, {report.negative_pass} neg-pass")

    return report


def print_summary(report: BulkReport) -> str:
    """Print and return the summary."""
    lines = []
    lines.append(f"\n{'='*70}")
    lines.append("  BULK TEST SUMMARY")
    lines.append(f"{'='*70}")
    lines.append(f"  Total rules tested:   {report.total}")
    lines.append("")
    lines.append(f"  Parse OK:             {report.parse_ok}")
    lines.append(f"  Parse FAIL:           {report.parse_fail}")
    lines.append("")
    lines.append(f"  Positive match PASS:  {report.positive_pass}")
    lines.append(f"  Positive match FAIL:  {report.positive_fail}  (synthetic log didn't trigger match)")
    lines.append(f"  Positive match SKIP:  {report.positive_skip}")
    lines.append("")
    lines.append(f"  Negative match PASS:  {report.negative_pass}")
    lines.append(f"  Negative match FAIL:  {report.negative_fail}  (false positive on junk event)")
    lines.append(f"  Negative match SKIP:  {report.negative_skip}")
    lines.append(f"{'='*70}")

    parse_pct = (report.parse_ok / report.total * 100) if report.total else 0
    lines.append(f"  Parse success rate:   {parse_pct:.1f}%")

    testable = report.positive_pass + report.positive_fail
    if testable:
        pos_pct = report.positive_pass / testable * 100
        lines.append(f"  Positive match rate:  {pos_pct:.1f}% of {testable} testable rules")

    lines.append(f"{'='*70}\n")

    text = "\n".join(lines)
    print(text)
    return text


def save_report(report: BulkReport, output_path: str = "bulk_test_report.txt"):
    """Save detailed results to a file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("SIGMA RULE BULK TEST REPORT\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total rules: {report.total}\n\n")

        # Parse failures
        failures = [r for r in report.results if not r.parse_ok]
        if failures:
            f.write(f"\n--- PARSE FAILURES ({len(failures)}) ---\n")
            for r in failures:
                f.write(f"  {r.path}\n    Error: {r.parse_error}\n\n")

        # Positive match failures
        pos_fails = [r for r in report.results if r.positive_match is False]
        if pos_fails:
            f.write(f"\n--- POSITIVE MATCH FAILURES ({len(pos_fails)}) ---\n")
            for r in pos_fails:
                f.write(f"  {r.path} — {r.title}\n")
                if r.notes:
                    f.write(f"    Note: {r.notes}\n")
                f.write("\n")

        # Negative match failures
        neg_fails = [r for r in report.results if r.negative_clean is False]
        if neg_fails:
            f.write(f"\n--- NEGATIVE MATCH FAILURES / FALSE POSITIVES ({len(neg_fails)}) ---\n")
            for r in neg_fails:
                f.write(f"  {r.path} — {r.title}\n")
                if r.notes:
                    f.write(f"    Note: {r.notes}\n")
                f.write("\n")

        # Summary
        f.write(print_summary(report))

    print(f"  Report saved to: {os.path.abspath(output_path)}")


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.tests.bulk_test <rules_directory>")
        print("Example: python -m app.tests.bulk_test sigma/rules")
        sys.exit(1)

    rules_dir = sys.argv[1]
    start = time.time()
    report = run_bulk_test(rules_dir)
    elapsed = time.time() - start

    print_summary(report)
    print(f"  Completed in {elapsed:.1f}s")

    save_report(report)
