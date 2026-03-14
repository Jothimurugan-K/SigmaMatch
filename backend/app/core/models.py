"""Pydantic models for the Sigma rule matcher."""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Sigma rule internal model
# ---------------------------------------------------------------------------

class SigmaModifier(str, enum.Enum):
    """Supported Sigma detection value modifiers."""

    EQUALS = "equals"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    RE = "re"
    NOT_CONTAINS = "not_contains"
    NOT_STARTSWITH = "not_startswith"
    NOT_ENDSWITH = "not_endswith"
    NOT_RE = "not_re"


class FieldCondition(BaseModel):
    """A single field-level condition, e.g. CommandLine|contains: 'powershell'."""

    field: str
    modifiers: list[SigmaModifier] = Field(default_factory=lambda: [SigmaModifier.EQUALS])
    case_insensitive: bool = True  # nocase is default in Sigma
    values: list[str]  # OR – any value matching is a hit


class SelectionBlock(BaseModel):
    """One named selection block (AND of field conditions)."""

    name: str
    conditions: list[FieldCondition]  # all must match (AND)


class LogSource(BaseModel):
    product: str | None = None
    category: str | None = None
    service: str | None = None


class SigmaRule(BaseModel):
    """Internal representation of a parsed Sigma rule."""

    title: str = ""
    rule_id: str = ""
    status: str = ""
    level: str = ""
    description: str = ""
    logsource: LogSource = Field(default_factory=LogSource)
    selections: list[SelectionBlock] = Field(default_factory=list)
    condition: str = ""
    timeframe: str = ""
    raw_detection: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Match result models
# ---------------------------------------------------------------------------

class FieldMatch(BaseModel):
    """Details about a single field that matched."""

    field: str
    modifier: str
    expected: list[str]
    actual: str


class EventMatch(BaseModel):
    """One matched log event."""

    event_index: int
    matched_selections: list[str]
    matched_fields: list[FieldMatch]
    explanation: str


class MatchResult(BaseModel):
    """Overall result returned by the matcher."""

    matched: bool
    match_count: int = 0
    total_events: int = 0
    matches: list[EventMatch] = Field(default_factory=list)
    explanation: str = ""
    warnings: list[str] = Field(default_factory=list)


class RuleMatchResult(BaseModel):
    """Result for a single rule in a batch check."""

    rule_title: str = ""
    rule_id: str = ""
    result: MatchResult
    error: str = ""


class BatchMatchResult(BaseModel):
    """Overall result for a multi-rule batch check."""

    total_rules: int = 0
    rules_matched: int = 0
    total_events: int = 0
    results: list[RuleMatchResult] = Field(default_factory=list)
    explanation: str = ""


# ---------------------------------------------------------------------------
# Validation models
# ---------------------------------------------------------------------------

class Issue(BaseModel):
    severity: str = "error"  # "error" | "warning" | "info"
    message: str


class ValidationResult(BaseModel):
    valid: bool
    issues: list[Issue] = Field(default_factory=list)
    title: str = ""
    logsource: LogSource | None = None


class RuleValidationResult(BaseModel):
    """Validation result for one rule in a batch."""

    rule_title: str = ""
    result: ValidationResult


class BatchValidationResult(BaseModel):
    """Overall result for batch rule validation."""

    total_rules: int = 0
    valid_count: int = 0
    results: list[RuleValidationResult] = Field(default_factory=list)
