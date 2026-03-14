"""Unit tests for the Sigma matching logic."""

import pytest

from app.core.matcher import match_events
from app.core.parser import parse_rule
from app.core.validators import validate_rule


# ---------------------------------------------------------------------------
# Sample rules
# ---------------------------------------------------------------------------

RULE_POWERSHELL = """\
title: Suspicious PowerShell Encoded Command
id: 11111111-2222-3333-4444-555555555555
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "powershell"
      - "-enc"
  condition: selection
level: medium
"""

RULE_OKTA_LOCKOUT = """\
title: Okta User Locked Out
id: 22222222-3333-4444-5555-666666666666
status: test
logsource:
  product: okta
  service: okta
detection:
  selection:
    eventType|equals:
      - "user.account.lock"
  condition: selection
level: high
"""

RULE_1_OF_SELECTION = """\
title: Multi Selection Test
id: 33333333-4444-5555-6666-777777777777
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection_cmd:
    CommandLine|contains: "cmd.exe"
  selection_ps:
    CommandLine|contains: "powershell"
  condition: 1 of selection_*
level: medium
"""

RULE_AND_NOT = """\
title: Selection AND NOT filter
id: 44444444-5555-6666-7777-888888888888
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: "\\\\explorer.exe"
  filter:
    Image|contains: "legitimate"
  condition: selection and not filter
level: low
"""

RULE_STARTSWITH = """\
title: StartsWith test
id: 55555555-6666-7777-8888-999999999999
status: test
logsource:
  product: linux
  service: sshd
detection:
  selection:
    message|startswith: "Failed password"
  condition: selection
level: low
"""

RULE_REGEX = """\
title: Regex test
id: 66666666-7777-8888-9999-aaaaaaaaaaaa
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|re: "powershell.*-e(nc|ncodedcommand)"
  condition: selection
level: high
"""

RULE_ALL_OF = """\
title: All of selections
id: 77777777-8888-9999-aaaa-bbbbbbbbbbbb
status: test
logsource:
  product: windows
detection:
  selection_user:
    User|equals: "admin"
  selection_action:
    Action|equals: "login"
  condition: all of selection_*
level: high
"""


# ---------------------------------------------------------------------------
# Test: positive match — PowerShell contains
# ---------------------------------------------------------------------------

class TestPositiveMatch:
    def test_powershell_contains_match(self):
        rule = parse_rule(RULE_POWERSHELL)
        events = [
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell -enc SQBtAG...",
            }
        ]
        result = match_events(rule, events)
        assert result.matched is True
        assert result.match_count == 1
        assert result.matches[0].matched_selections == ["selection"]
        assert any(f.field == "CommandLine" for f in result.matches[0].matched_fields)

    def test_powershell_case_insensitive(self):
        rule = parse_rule(RULE_POWERSHELL)
        events = [
            {"CommandLine": "POWERSHELL -ENC abc123"}
        ]
        result = match_events(rule, events)
        assert result.matched is True


# ---------------------------------------------------------------------------
# Test: negative match
# ---------------------------------------------------------------------------

class TestNegativeMatch:
    def test_no_match_when_field_missing(self):
        rule = parse_rule(RULE_POWERSHELL)
        events = [{"EventID": 1, "Image": "cmd.exe"}]
        result = match_events(rule, events)
        assert result.matched is False
        assert result.match_count == 0

    def test_no_match_wrong_value(self):
        rule = parse_rule(RULE_POWERSHELL)
        events = [{"CommandLine": "cmd.exe /c dir"}]
        result = match_events(rule, events)
        # "contains" requires both "powershell" AND "-enc" to appear.
        # "cmd.exe /c dir" contains neither → no match
        assert result.matched is False


# ---------------------------------------------------------------------------
# Test: 1 of selection_*
# ---------------------------------------------------------------------------

class TestOneOfSelection:
    def test_matches_first_selection(self):
        rule = parse_rule(RULE_1_OF_SELECTION)
        events = [{"CommandLine": "cmd.exe /c whoami"}]
        result = match_events(rule, events)
        assert result.matched is True
        assert "selection_cmd" in result.matches[0].matched_selections

    def test_matches_second_selection(self):
        rule = parse_rule(RULE_1_OF_SELECTION)
        events = [{"CommandLine": "powershell Get-Process"}]
        result = match_events(rule, events)
        assert result.matched is True
        assert "selection_ps" in result.matches[0].matched_selections

    def test_no_match_neither(self):
        rule = parse_rule(RULE_1_OF_SELECTION)
        events = [{"CommandLine": "notepad.exe"}]
        result = match_events(rule, events)
        assert result.matched is False


# ---------------------------------------------------------------------------
# Test: selection AND NOT filter
# ---------------------------------------------------------------------------

class TestAndNotCondition:
    def test_match_selection_not_filtered(self):
        rule = parse_rule(RULE_AND_NOT)
        events = [
            {
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": "C:\\malware\\evil.exe",
            }
        ]
        result = match_events(rule, events)
        assert result.matched is True

    def test_filtered_out(self):
        rule = parse_rule(RULE_AND_NOT)
        events = [
            {
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": "C:\\legitimate_app\\tool.exe",
            }
        ]
        result = match_events(rule, events)
        assert result.matched is False


# ---------------------------------------------------------------------------
# Test: startswith modifier
# ---------------------------------------------------------------------------

class TestStartsWith:
    def test_startswith_match(self):
        rule = parse_rule(RULE_STARTSWITH)
        events = [{"message": "Failed password for root from 10.0.0.1"}]
        result = match_events(rule, events)
        assert result.matched is True

    def test_startswith_no_match(self):
        rule = parse_rule(RULE_STARTSWITH)
        events = [{"message": "Accepted password for user1"}]
        result = match_events(rule, events)
        assert result.matched is False


# ---------------------------------------------------------------------------
# Test: regex modifier
# ---------------------------------------------------------------------------

class TestRegex:
    def test_regex_match(self):
        rule = parse_rule(RULE_REGEX)
        events = [{"CommandLine": "powershell.exe -encodedcommand AAAA"}]
        result = match_events(rule, events)
        assert result.matched is True

    def test_regex_no_match(self):
        rule = parse_rule(RULE_REGEX)
        events = [{"CommandLine": "powershell.exe -File script.ps1"}]
        result = match_events(rule, events)
        assert result.matched is False


# ---------------------------------------------------------------------------
# Test: all of selection_*
# ---------------------------------------------------------------------------

class TestAllOfSelection:
    def test_all_of_match(self):
        rule = parse_rule(RULE_ALL_OF)
        events = [{"User": "admin", "Action": "login"}]
        result = match_events(rule, events)
        assert result.matched is True
        assert len(result.matches[0].matched_selections) == 2

    def test_all_of_partial_no_match(self):
        rule = parse_rule(RULE_ALL_OF)
        events = [{"User": "admin", "Action": "logout"}]
        result = match_events(rule, events)
        assert result.matched is False


# ---------------------------------------------------------------------------
# Test: multiple events, some match
# ---------------------------------------------------------------------------

class TestMultipleEvents:
    def test_mixed_events(self):
        rule = parse_rule(RULE_POWERSHELL)
        events = [
            {"CommandLine": "notepad.exe"},
            {"CommandLine": "powershell -enc AAAA"},
            {"CommandLine": "calc.exe"},
            {"CommandLine": "powershell.exe -enc BBBB"},
        ]
        result = match_events(rule, events)
        assert result.matched is True
        assert result.match_count == 2
        assert result.total_events == 4
        assert result.matches[0].event_index == 1
        assert result.matches[1].event_index == 3


# ---------------------------------------------------------------------------
# Test: validator
# ---------------------------------------------------------------------------

class TestValidator:
    def test_valid_rule(self):
        result = validate_rule(RULE_POWERSHELL)
        assert result.valid is True
        assert result.title == "Suspicious PowerShell Encoded Command"

    def test_empty_rule(self):
        result = validate_rule("")
        assert result.valid is False

    def test_invalid_yaml(self):
        result = validate_rule(":::not valid yaml:::")
        assert result.valid is False

    def test_missing_detection(self):
        result = validate_rule("title: test\n")
        assert result.valid is False
        assert any("detection" in i.message for i in result.issues)


# ---------------------------------------------------------------------------
# Test: equals modifier (Okta rule)
# ---------------------------------------------------------------------------

class TestEqualsModifier:
    def test_exact_match(self):
        rule = parse_rule(RULE_OKTA_LOCKOUT)
        events = [{"eventType": "user.account.lock", "actor": "someone"}]
        result = match_events(rule, events)
        assert result.matched is True

    def test_no_exact_match(self):
        rule = parse_rule(RULE_OKTA_LOCKOUT)
        events = [{"eventType": "user.session.start"}]
        result = match_events(rule, events)
        assert result.matched is False
