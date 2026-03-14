"""Parse Sigma YAML text into internal SigmaRule model."""

from __future__ import annotations

import yaml

from .models import (
    FieldCondition,
    LogSource,
    SelectionBlock,
    SigmaModifier,
    SigmaRule,
)

_MODIFIER_MAP: dict[str, SigmaModifier] = {
    "contains": SigmaModifier.CONTAINS,
    "startswith": SigmaModifier.STARTSWITH,
    "endswith": SigmaModifier.ENDSWITH,
    "re": SigmaModifier.RE,
    "equals": SigmaModifier.EQUALS,
    "not_contains": SigmaModifier.NOT_CONTAINS,
    "not_startswith": SigmaModifier.NOT_STARTSWITH,
    "not_endswith": SigmaModifier.NOT_ENDSWITH,
    "not_re": SigmaModifier.NOT_RE,
}


def _parse_field_key(key: str) -> tuple[str, list[SigmaModifier], bool]:
    """Parse a detection field key like 'CommandLine|contains|nocase'.

    Returns (field_name, modifiers, case_insensitive).
    """
    parts = key.split("|")
    field_name = parts[0]
    modifiers: list[SigmaModifier] = []
    case_insensitive = True  # Sigma default

    for part in parts[1:]:
        lower = part.lower()
        if lower == "nocase":
            case_insensitive = True
            continue
        if lower in _MODIFIER_MAP:
            modifiers.append(_MODIFIER_MAP[lower])
        # Unknown modifiers are silently ignored in MVP

    if not modifiers:
        modifiers = [SigmaModifier.EQUALS]

    return field_name, modifiers, case_insensitive


def _coerce_to_str_list(value: object) -> list[str]:
    """Ensure value is a list of strings."""
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _parse_selection(name: str, data: dict) -> SelectionBlock:
    """Parse a single selection block from the detection section."""
    conditions: list[FieldCondition] = []
    for key, value in data.items():
        field_name, modifiers, nocase = _parse_field_key(key)
        conditions.append(
            FieldCondition(
                field=field_name,
                modifiers=modifiers,
                case_insensitive=nocase,
                values=_coerce_to_str_list(value),
            )
        )
    return SelectionBlock(name=name, conditions=conditions)


def parse_rule(yaml_text: str) -> SigmaRule:
    """Parse a Sigma rule YAML string into a SigmaRule model.

    Raises ValueError on invalid YAML or missing required fields.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if not isinstance(doc, dict):
        raise ValueError("Sigma rule must be a YAML mapping (dict) at top level.")

    return _build_rule(doc)


def parse_rules(yaml_text: str) -> list[SigmaRule]:
    """Parse one or more Sigma rules from a multi-document YAML string.

    Documents are separated by '---'. Returns a list of SigmaRule objects.
    Raises ValueError if no valid documents are found.
    """
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    rules: list[SigmaRule] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        rules.append(_build_rule(doc))

    if not rules:
        raise ValueError("No valid Sigma rule documents found.")
    return rules


def _build_rule(doc: dict) -> SigmaRule:
    """Build a SigmaRule from a parsed YAML dict.

    Raises ValueError on missing required fields.
    """

    detection = doc.get("detection")
    if not detection or not isinstance(detection, dict):
        raise ValueError("Sigma rule is missing a 'detection' section.")

    condition = detection.get("condition")
    if not condition:
        raise ValueError("Sigma detection is missing a 'condition' field.")

    # Parse selections (everything in detection except 'condition' and 'timeframe')
    selections: list[SelectionBlock] = []
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, dict):
            selections.append(_parse_selection(key, value))
        elif isinstance(value, list):
            # List of dicts → each dict is OR'd, fields within a dict are AND'd
            # Flatten to a single selection with OR'd values per field
            merged: dict[str, list] = {}
            for item in value:
                if isinstance(item, dict):
                    for k, v in item.items():
                        merged.setdefault(k, []).extend(
                            _coerce_to_str_list(v)
                        )
            if merged:
                conditions = []
                for k, vals in merged.items():
                    field_name, modifiers, nocase = _parse_field_key(k)
                    conditions.append(
                        FieldCondition(
                            field=field_name,
                            modifiers=modifiers,
                            case_insensitive=nocase,
                            values=vals,
                        )
                    )
                selections.append(SelectionBlock(name=key, conditions=conditions))

    logsource_raw = doc.get("logsource", {})
    logsource = LogSource(
        product=logsource_raw.get("product"),
        category=logsource_raw.get("category"),
        service=logsource_raw.get("service"),
    )

    return SigmaRule(
        title=str(doc.get("title", "")),
        rule_id=str(doc.get("id", "")),
        status=str(doc.get("status", "")),
        level=str(doc.get("level", "")),
        description=str(doc.get("description", "")),
        logsource=logsource,
        selections=selections,
        condition=str(condition),
        timeframe=str(detection.get("timeframe", "")),
        raw_detection=detection,
    )
