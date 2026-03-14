"""Validate Sigma rule YAML before matching."""

from __future__ import annotations

import yaml

from .models import BatchValidationResult, Issue, LogSource, RuleValidationResult, ValidationResult
from .parser import parse_rule


def _validate_single(rule_doc: dict | None, raw_yaml: str | None = None) -> ValidationResult:
    """Validate a single parsed or raw Sigma rule."""
    issues: list[Issue] = []

    # If we have raw YAML, parse it
    if raw_yaml is not None:
        try:
            rule = parse_rule(raw_yaml)
        except ValueError as exc:
            return ValidationResult(
                valid=False,
                issues=[Issue(severity="error", message=str(exc))],
            )
    else:
        # Build rule from already-parsed doc
        from .parser import _build_rule
        try:
            rule = _build_rule(rule_doc)
        except ValueError as exc:
            return ValidationResult(
                valid=False,
                issues=[Issue(severity="error", message=str(exc))],
            )

    if not rule.title:
        issues.append(Issue(severity="warning", message="Rule is missing a 'title'."))
    if not rule.rule_id:
        issues.append(Issue(severity="warning", message="Rule is missing an 'id' (UUID)."))
    if not rule.level:
        issues.append(Issue(severity="info", message="Rule is missing 'level'."))
    if not rule.logsource.product and not rule.logsource.category and not rule.logsource.service:
        issues.append(
            Issue(severity="warning", message="Rule 'logsource' has no product, category, or service.")
        )
    if not rule.selections:
        issues.append(Issue(severity="error", message="No selections found in detection block."))
    if rule.timeframe:
        issues.append(
            Issue(
                severity="info",
                message=f"Rule uses 'timeframe: {rule.timeframe}' — temporal aggregation is not yet supported. "
                        "Match results will ignore the time-window constraint.",
            )
        )

    has_error = any(i.severity == "error" for i in issues)
    return ValidationResult(
        valid=not has_error,
        issues=issues,
        title=rule.title,
        logsource=rule.logsource if (rule.logsource.product or rule.logsource.category or rule.logsource.service) else None,
    )


def validate_rule(yaml_text: str) -> ValidationResult:
    """Validate a single Sigma rule YAML string."""
    if not yaml_text or not yaml_text.strip():
        return ValidationResult(
            valid=False,
            issues=[Issue(severity="error", message="Rule YAML is empty.")],
        )
    return _validate_single(rule_doc=None, raw_yaml=yaml_text)


def validate_rules(yaml_text: str) -> BatchValidationResult:
    """Validate multiple Sigma rules from a multi-document YAML string."""
    if not yaml_text or not yaml_text.strip():
        return BatchValidationResult(
            total_rules=0,
            valid_count=0,
            results=[RuleValidationResult(
                result=ValidationResult(
                    valid=False,
                    issues=[Issue(severity="error", message="Rule YAML is empty.")],
                )
            )],
        )

    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as exc:
        return BatchValidationResult(
            total_rules=0,
            valid_count=0,
            results=[RuleValidationResult(
                result=ValidationResult(
                    valid=False,
                    issues=[Issue(severity="error", message=f"Invalid YAML: {exc}")],
                )
            )],
        )

    results: list[RuleValidationResult] = []
    valid_count = 0
    for doc in docs:
        if not isinstance(doc, dict):
            results.append(RuleValidationResult(
                result=ValidationResult(
                    valid=False,
                    issues=[Issue(severity="error", message="Document is not a YAML mapping.")],
                )
            ))
            continue
        vr = _validate_single(rule_doc=doc)
        if vr.valid:
            valid_count += 1
        results.append(RuleValidationResult(
            rule_title=vr.title,
            result=vr,
        ))

    return BatchValidationResult(
        total_rules=len(results),
        valid_count=valid_count,
        results=results,
    )
