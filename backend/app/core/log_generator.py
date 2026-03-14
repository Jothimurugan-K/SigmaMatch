"""Synthetic log generator — creates fake log events from parsed Sigma rules.

Given a SigmaRule, this module generates:
  1. A POSITIVE event that should trigger a match.
  2. A NEGATIVE event that should NOT trigger a match.

This enables bulk-testing the parser + matcher against any Sigma rule
even when real log data is unavailable.
"""

from __future__ import annotations

from app.core.models import FieldCondition, SigmaModifier, SigmaRule


def _positive_value(condition: FieldCondition) -> str:
    """Create a field value that satisfies the condition."""
    # Use the first value in the OR list as the seed
    seed = condition.values[0] if condition.values else "test"
    modifier = condition.modifiers[0] if condition.modifiers else SigmaModifier.EQUALS

    if modifier == SigmaModifier.EQUALS:
        return seed
    elif modifier == SigmaModifier.CONTAINS:
        return f"prefix_{seed}_suffix"
    elif modifier == SigmaModifier.STARTSWITH:
        return f"{seed}_trailing"
    elif modifier == SigmaModifier.ENDSWITH:
        return f"leading_{seed}"
    elif modifier == SigmaModifier.RE:
        # For regex, try to produce a literal string that would match.
        # Strip common regex anchors/metacharacters and use a plausible value.
        import re
        # Replace common regex patterns with literal equivalents
        literal = seed
        literal = literal.replace(".*", "_SOMETHING_")
        literal = literal.replace(".+", "_X_")
        literal = literal.replace("\\d+", "123")
        literal = literal.replace("\\d", "1")
        literal = literal.replace("\\w+", "word")
        literal = literal.replace("\\s+", " ")
        literal = literal.replace("\\s", " ")
        # Remove anchors
        literal = literal.lstrip("^").rstrip("$")
        # Remove character class alternation — pick first option
        literal = re.sub(r"\(([^|)]+)\|[^)]*\)", r"\1", literal)
        # Remove remaining regex syntax that isn't literal
        literal = re.sub(r"[\\?+*\[\]{}()^$]", "", literal)
        return literal if literal.strip() else seed

    return seed


def _negative_value(condition: FieldCondition) -> str:
    """Create a field value that does NOT satisfy the condition."""
    return "__NOMATCH_SYNTHETIC_VALUE__"


def generate_positive_event(rule: SigmaRule) -> dict:
    """Build a synthetic log event that should match the rule.

    Populates every field referenced in every selection with a value
    designed to satisfy that selection's conditions.
    """
    event: dict[str, str] = {}
    for sel in rule.selections:
        for cond in sel.conditions:
            if cond.field not in event:
                event[cond.field] = _positive_value(cond)
    return event


def generate_negative_event(rule: SigmaRule) -> dict:
    """Build a synthetic log event that should NOT match the rule.

    Puts unrelated values in every referenced field so no selection triggers.
    """
    event: dict[str, str] = {}
    for sel in rule.selections:
        for cond in sel.conditions:
            if cond.field not in event:
                event[cond.field] = _negative_value(cond)
    return event
