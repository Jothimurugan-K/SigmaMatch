"""API routes for SigmaMatch."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.log_parsers import detect_and_parse
from app.core.matcher import MatchTimeoutError, match_events
from app.core.models import BatchMatchResult, BatchValidationResult, MatchResult, RuleMatchResult, ValidationResult
from app.core.parser import parse_rule, parse_rules
from app.core.validators import validate_rule, validate_rules

from app.core.config import limiter

router = APIRouter(prefix="/api")

MAX_BODY_SIZE = 5 * 1024 * 1024  # 5 MB


# -- Request schemas --------------------------------------------------------

class ValidateRequest(BaseModel):
    rule_yaml: str = Field(..., max_length=MAX_BODY_SIZE)


class CheckRequest(BaseModel):
    rule_yaml: str = Field(..., max_length=MAX_BODY_SIZE)
    logs_text: str = Field(..., max_length=MAX_BODY_SIZE)


# -- Endpoints --------------------------------------------------------------

@router.post("/validate", response_model=ValidationResult)
@limiter.limit("60/minute")
async def api_validate(request: Request, req: ValidateRequest) -> ValidationResult:
    """Validate a Sigma rule YAML and return issues + metadata."""
    return validate_rule(req.rule_yaml)


@router.post("/batch-validate", response_model=BatchValidationResult)
@limiter.limit("30/minute")
async def api_batch_validate(request: Request, req: ValidateRequest) -> BatchValidationResult:
    """Validate multiple Sigma rules (--- separated)."""
    return validate_rules(req.rule_yaml)


@router.post("/check", response_model=MatchResult)
@limiter.limit("30/minute")
async def api_check(request: Request, req: CheckRequest) -> MatchResult:
    """Parse a Sigma rule, parse log events, and return match results."""
    # Parse rule
    try:
        rule = parse_rule(req.rule_yaml)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid Sigma rule: {exc}")

    # Parse log events (JSON array or NDJSON)
    events = _parse_logs(req.logs_text)
    if not events:
        raise HTTPException(status_code=422, detail="No valid log events found in input.")

    # Run matcher in a thread so it doesn't block the async event loop
    from app.core.config import MATCH_TIMEOUT
    try:
        result = await asyncio.to_thread(match_events, rule, events, timeout_seconds=MATCH_TIMEOUT)
    except MatchTimeoutError:
        raise HTTPException(
            status_code=408,
            detail=f"Match operation timed out after {MATCH_TIMEOUT} seconds. "
                   f"Try reducing the number of log events or simplifying the rule.",
        )

    if rule.timeframe:
        result.warnings.append(
            f"This rule uses 'timeframe: {rule.timeframe}' which is not yet evaluated. "
            "Matches shown are without the time-window constraint."
        )
    return result


def _parse_logs(text: str) -> list[dict]:
    """Parse JSON (single object, array) or NDJSON into a list of dicts."""
    text = text.strip()
    if not text:
        return []

    # Try JSON array or single object first
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [e for e in parsed if isinstance(e, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON (one JSON object per line)
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except json.JSONDecodeError:
            continue
    if events:
        return events

    # Fall back to non-JSON formats: XML, CSV/TSV, Key=Value
    result = detect_and_parse(text)
    if result:
        return result

    return []


# -- Batch check ------------------------------------------------------------

class BatchCheckRequest(BaseModel):
    rule_yaml: str = Field(..., max_length=MAX_BODY_SIZE)
    logs_text: str = Field(..., max_length=MAX_BODY_SIZE)


@router.post("/batch-check", response_model=BatchMatchResult)
@limiter.limit("10/minute")
async def api_batch_check(request: Request, req: BatchCheckRequest) -> BatchMatchResult:
    """Parse multiple Sigma rules (--- separated), match each against logs."""
    try:
        rules = parse_rules(req.rule_yaml)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid Sigma rules: {exc}")

    events = _parse_logs(req.logs_text)
    if not events:
        raise HTTPException(status_code=422, detail="No valid log events found in input.")

    from app.core.config import MATCH_TIMEOUT

    # Run the entire batch loop in a thread to avoid blocking the event loop
    async def _run_batch():
        import time
        results: list[RuleMatchResult] = []
        rules_matched = 0
        start_time = time.monotonic()

        for rule in rules:
            if MATCH_TIMEOUT is not None and (time.monotonic() - start_time) > MATCH_TIMEOUT:
                raise HTTPException(
                    status_code=408,
                    detail=f"Batch operation timed out after {MATCH_TIMEOUT} seconds. "
                           f"Processed {len(results)} of {len(rules)} rules. "
                           f"Try fewer rules or fewer log events.",
                )

            remaining = None
            if MATCH_TIMEOUT is not None:
                remaining = MATCH_TIMEOUT - (time.monotonic() - start_time)
                if remaining <= 0:
                    remaining = 0.1

            try:
                result = await asyncio.to_thread(match_events, rule, events, timeout_seconds=remaining)
                if rule.timeframe:
                    result.warnings.append(
                        f"This rule uses 'timeframe: {rule.timeframe}' which is not yet evaluated. "
                        "Matches shown are without the time-window constraint."
                    )
                if result.matched:
                    rules_matched += 1
                results.append(RuleMatchResult(
                    rule_title=rule.title,
                    rule_id=rule.rule_id,
                    result=result,
                ))
            except MatchTimeoutError:
                raise HTTPException(
                    status_code=408,
                    detail=f"Batch operation timed out after {MATCH_TIMEOUT} seconds. "
                           f"Processed {len(results)} of {len(rules)} rules. "
                           f"Try fewer rules or fewer log events.",
                )
            except ValueError as exc:
                results.append(RuleMatchResult(
                    rule_title=rule.title,
                    rule_id=rule.rule_id,
                    result=MatchResult(matched=False, total_events=len(events)),
                    error=str(exc),
                ))

        summary = f"{rules_matched} of {len(rules)} rules matched across {len(events)} events."
        return BatchMatchResult(
            total_rules=len(rules),
            rules_matched=rules_matched,
            total_events=len(events),
            results=results,
            explanation=summary,
        )

    return await _run_batch()
