"""Sigma rule matcher – evaluates a parsed SigmaRule against log events."""

from __future__ import annotations

import re
import time
from typing import Iterable

from .models import (
    EventMatch,
    FieldCondition,
    FieldMatch,
    MatchResult,
    SelectionBlock,
    SigmaModifier,
    SigmaRule,
)


# ---------------------------------------------------------------------------
# Field-level matching
# ---------------------------------------------------------------------------

def _field_matches(condition: FieldCondition, event: dict) -> FieldMatch | None:
    """Check whether a single FieldCondition matches an event.

    Returns a FieldMatch if it matches, else None.
    The condition's values list is OR'd – any value hit is enough.
    All modifiers in the modifier chain are applied (AND of modifiers).
    """
    raw_value = event.get(condition.field)
    if raw_value is None:
        return None

    actual = str(raw_value)
    compare_actual = actual.lower() if condition.case_insensitive else actual

    for modifier in condition.modifiers:
        matched_value: str | None = None
        for val in condition.values:
            compare_val = val.lower() if condition.case_insensitive else val

            if modifier == SigmaModifier.EQUALS:
                if compare_actual == compare_val:
                    matched_value = val
                    break
            elif modifier == SigmaModifier.CONTAINS:
                if compare_val in compare_actual:
                    matched_value = val
                    break
            elif modifier == SigmaModifier.STARTSWITH:
                if compare_actual.startswith(compare_val):
                    matched_value = val
                    break
            elif modifier == SigmaModifier.ENDSWITH:
                if compare_actual.endswith(compare_val):
                    matched_value = val
                    break
            elif modifier == SigmaModifier.RE:
                flags = re.IGNORECASE if condition.case_insensitive else 0
                if re.search(val, actual, flags):
                    matched_value = val
                    break
            elif modifier == SigmaModifier.NOT_CONTAINS:
                if compare_val in compare_actual:
                    matched_value = None
                    break  # found a match → negation fails
                matched_value = val  # none matched → negation passes
            elif modifier == SigmaModifier.NOT_STARTSWITH:
                if compare_actual.startswith(compare_val):
                    matched_value = None
                    break
                matched_value = val
            elif modifier == SigmaModifier.NOT_ENDSWITH:
                if compare_actual.endswith(compare_val):
                    matched_value = None
                    break
                matched_value = val
            elif modifier == SigmaModifier.NOT_RE:
                flags = re.IGNORECASE if condition.case_insensitive else 0
                if re.search(val, actual, flags):
                    matched_value = None
                    break
                matched_value = val

        if matched_value is None:
            return None  # modifier not satisfied

    # All modifiers satisfied
    return FieldMatch(
        field=condition.field,
        modifier=condition.modifiers[0].value,
        expected=condition.values,
        actual=actual,
    )


# ---------------------------------------------------------------------------
# Selection-level matching
# ---------------------------------------------------------------------------

def _selection_matches(
    selection: SelectionBlock, event: dict
) -> list[FieldMatch]:
    """Evaluate a selection block against an event.

    All conditions must match (AND). Returns list of FieldMatch on success,
    empty list on failure.
    """
    field_matches: list[FieldMatch] = []
    for cond in selection.conditions:
        fm = _field_matches(cond, event)
        if fm is None:
            return []
        field_matches.append(fm)
    return field_matches


# ---------------------------------------------------------------------------
# Condition expression evaluator
# ---------------------------------------------------------------------------

class _ConditionEvaluator:
    """Evaluate the Sigma `condition` expression string.

    Supported syntax (MVP):
        - <selection_name>
        - selection1 and selection2
        - selection1 or selection2
        - not <selection_name>
        - 1 of selection_*  /  all of selection_*  /  1 of them
        - Parentheses for grouping
    """

    def __init__(
        self,
        rule: SigmaRule,
        event: dict,
    ):
        self._selections = {s.name: s for s in rule.selections}
        self._event = event
        self._cache: dict[str, list[FieldMatch]] = {}

    def _eval_selection(self, name: str) -> list[FieldMatch]:
        if name not in self._cache:
            sel = self._selections.get(name)
            if sel is None:
                self._cache[name] = []
            else:
                self._cache[name] = _selection_matches(sel, self._event)
        return self._cache[name]

    def evaluate(self, condition: str) -> tuple[bool, list[str], list[FieldMatch]]:
        """Return (matched, list_of_triggered_selection_names, field_matches)."""
        tokens = self._tokenize(condition)
        (result, sels, fms), _ = self._bool_eval(tokens, 0)
        return result, sels, fms

    # -- tokenizer -----------------------------------------------------------

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        """Split condition into tokens."""
        # Insert spaces around parens
        condition = condition.replace("(", " ( ").replace(")", " ) ")
        return condition.split()

    # -- recursive descent parser --------------------------------------------

    def _eval_expr(
        self, tokens: list[str]
    ) -> tuple[bool, list[str], list[FieldMatch]]:
        """Simple expression evaluator — entry via _bool_eval."""
        joined = " ".join(tokens)

        # --- n of pattern ---
        of_match = re.match(
            r"^(all|\d+)\s+of\s+(them|[\w*]+)$", joined.strip()
        )
        if of_match:
            return self._eval_of(of_match.group(1), of_match.group(2))

        # --- recursive boolean parse ---
        return self._bool_eval(tokens, 0)[0]

    def _eval_of(
        self, quantifier: str, pattern: str
    ) -> tuple[bool, list[str], list[FieldMatch]]:
        """Evaluate '1 of selection_*' style conditions."""
        if pattern == "them":
            names = list(self._selections.keys())
        elif "*" in pattern:
            prefix = pattern.replace("*", "")
            names = [n for n in self._selections if n.startswith(prefix)]
        else:
            names = [pattern]

        matched_sels: list[str] = []
        all_fms: list[FieldMatch] = []

        for name in names:
            fms = self._eval_selection(name)
            if fms:
                matched_sels.append(name)
                all_fms.extend(fms)

        count = len(matched_sels)
        if quantifier == "all":
            ok = count == len(names) and len(names) > 0
        else:
            ok = count >= int(quantifier)

        return ok, matched_sels, all_fms

    def _bool_eval(
        self, tokens: list[str], pos: int
    ) -> tuple[tuple[bool, list[str], list[FieldMatch]], int]:
        """Recursive boolean expression evaluator.

        Grammar:
            expr     -> and_expr ('or' and_expr)*
            and_expr -> not_expr ('and' not_expr)*
            not_expr -> 'not' not_expr | atom
            atom     -> '(' expr ')' | of_expr | selection_name
        """
        left, pos = self._parse_and_expr(tokens, pos)

        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1  # skip 'or'
            right, pos = self._parse_and_expr(tokens, pos)
            combined_sels = left[1] + right[1]
            combined_fms = left[2] + right[2]
            left = (left[0] or right[0], combined_sels, combined_fms)

        return left, pos

    def _parse_and_expr(
        self, tokens: list[str], pos: int
    ) -> tuple[tuple[bool, list[str], list[FieldMatch]], int]:
        left, pos = self._parse_not_expr(tokens, pos)

        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            right, pos = self._parse_not_expr(tokens, pos)
            combined_sels = left[1] + right[1]
            combined_fms = left[2] + right[2]
            left = (left[0] and right[0], combined_sels, combined_fms)

        return left, pos

    def _parse_not_expr(
        self, tokens: list[str], pos: int
    ) -> tuple[tuple[bool, list[str], list[FieldMatch]], int]:
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            inner, pos = self._parse_not_expr(tokens, pos)
            return (not inner[0], inner[1], inner[2]), pos
        return self._parse_atom(tokens, pos)

    def _parse_atom(
        self, tokens: list[str], pos: int
    ) -> tuple[tuple[bool, list[str], list[FieldMatch]], int]:
        if pos >= len(tokens):
            return (False, [], []), pos

        token = tokens[pos]

        # Parenthesised expression
        if token == "(":
            pos += 1
            result, pos = self._bool_eval(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return result, pos

        # "N of pattern" — look ahead
        if pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
            quantifier = token
            pattern = tokens[pos + 2]
            pos += 3
            return self._eval_of(quantifier, pattern), pos

        if token.lower() == "all" and pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
            pattern = tokens[pos + 2]
            pos += 3
            return self._eval_of("all", pattern), pos

        # Plain selection name
        pos += 1
        fms = self._eval_selection(token)
        if fms:
            return (True, [token], fms), pos
        else:
            return (False, [], []), pos


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class MatchTimeoutError(Exception):
    """Raised when match_events exceeds the configured timeout."""


def match_events(
    rule: SigmaRule,
    events: Iterable[dict],
    *,
    max_matches: int = 100,
    timeout_seconds: float | None = None,
) -> MatchResult:
    """Evaluate a SigmaRule against an iterable of log events.

    Returns a MatchResult with up to `max_matches` individual event matches.
    Raises MatchTimeoutError if processing exceeds `timeout_seconds`.
    """
    matches: list[EventMatch] = []
    total = 0
    start_time = time.monotonic()

    for idx, event in enumerate(events):
        if timeout_seconds is not None and (time.monotonic() - start_time) > timeout_seconds:
            raise MatchTimeoutError(
                f"Match operation timed out after {timeout_seconds}s "
                f"(processed {total} of unknown total events)."
            )
        total += 1
        evaluator = _ConditionEvaluator(rule, event)
        matched, sel_names, field_matches = evaluator.evaluate(rule.condition)

        if matched and len(matches) < max_matches:
            parts = []
            for fm in field_matches:
                parts.append(
                    f"{fm.field} {fm.modifier} {fm.expected!r} (actual: {fm.actual!r})"
                )
            explanation = "; ".join(parts) if parts else "Condition evaluated to true."

            matches.append(
                EventMatch(
                    event_index=idx,
                    matched_selections=sel_names,
                    matched_fields=field_matches,
                    explanation=explanation,
                )
            )

    match_count = len(matches)

    if match_count > 0:
        summary = (
            f"Matched {match_count} of {total} events. "
            f"Selections triggered: {', '.join(matches[0].matched_selections)}."
        )
    else:
        summary = f"No matches found across {total} events."

    return MatchResult(
        matched=match_count > 0,
        match_count=match_count,
        total_events=total,
        matches=matches,
        explanation=summary,
    )
