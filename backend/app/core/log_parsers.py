"""Log format parsers for non-JSON log types.

Converts raw text in various log formats to list[dict] for the matcher.
Supported formats: Windows Event XML, CSV/TSV, Key=Value pairs.
"""

from __future__ import annotations

import csv
import io
import re

import defusedxml.ElementTree as ET


# ---------------------------------------------------------------------------
# Windows Event Log XML
# ---------------------------------------------------------------------------

def _xml_element_to_dict(elem) -> dict:
    """Flatten a Windows Event XML <Event> element into a flat dict."""
    record: dict[str, str] = {}

    # <System> fields — e.g. <EventID>4625</EventID>
    system = elem.find("{http://schemas.microsoft.com/win/2004/08/events/event}System")
    if system is None:
        system = elem.find("System")
    if system is not None:
        for child in system:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text and child.text.strip():
                record[tag] = child.text.strip()
            # Also capture attributes (e.g. <Provider Name="..."/>)
            for attr_name, attr_val in child.attrib.items():
                record[f"{tag}.{attr_name}"] = attr_val

    # <EventData> fields — e.g. <Data Name="TargetUserName">admin</Data>
    event_data = elem.find(
        "{http://schemas.microsoft.com/win/2004/08/events/event}EventData"
    )
    if event_data is None:
        event_data = elem.find("EventData")
    if event_data is not None:
        for data_elem in event_data:
            name = data_elem.attrib.get("Name", "")
            value = data_elem.text or ""
            if name:
                record[name] = value
            elif data_elem.text:
                tag = data_elem.tag.split("}")[-1] if "}" in data_elem.tag else data_elem.tag
                record[tag] = data_elem.text

    # <UserData> — some events use this instead of EventData
    user_data = elem.find(
        "{http://schemas.microsoft.com/win/2004/08/events/event}UserData"
    )
    if user_data is None:
        user_data = elem.find("UserData")
    if user_data is not None:
        for child in user_data:
            for sub in child:
                tag = sub.tag.split("}")[-1] if "}" in sub.tag else sub.tag
                if sub.text and sub.text.strip():
                    record[tag] = sub.text.strip()

    return record


def parse_xml_events(text: str) -> list[dict]:
    """Parse Windows Event Log XML into a list of flat dicts.

    Handles single <Event>, multiple <Event> elements, and <Events> wrapper.
    Uses defusedxml to prevent XXE and entity expansion attacks.
    """
    text = text.strip()
    if not text:
        return []

    # Wrap in a root if there are multiple <Event> elements without a wrapper
    if not text.startswith("<Events") and text.count("<Event") > 1:
        text = f"<Events>{text}</Events>"

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    events: list[dict] = []
    root_tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag

    if root_tag == "Event":
        record = _xml_element_to_dict(root)
        if record:
            events.append(record)
    else:
        # <Events> wrapper or other container
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        for event_elem in root.findall(f"{ns}Event"):
            record = _xml_element_to_dict(event_elem)
            if record:
                events.append(record)
        # Also try without namespace
        if not events:
            for event_elem in root.findall("Event"):
                record = _xml_element_to_dict(event_elem)
                if record:
                    events.append(record)

    return events


# ---------------------------------------------------------------------------
# CSV / TSV
# ---------------------------------------------------------------------------

def parse_csv_events(text: str) -> list[dict]:
    """Parse CSV or TSV text into a list of dicts (header row required).

    Auto-detects delimiter: if tabs outnumber commas in the first line, use TSV.
    """
    text = text.strip()
    if not text:
        return []

    lines = text.splitlines()
    if len(lines) < 2:
        return []  # Need at least header + one data row

    first_line = lines[0]
    # Auto-detect delimiter
    delimiter = "\t" if first_line.count("\t") > first_line.count(",") else ","

    try:
        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        events = [dict(row) for row in reader if any(v for v in row.values())]
        return events
    except csv.Error:
        return []


# ---------------------------------------------------------------------------
# Key=Value pairs
# ---------------------------------------------------------------------------

# Matches: key=value, key="quoted value", key='quoted value'
_KV_PATTERN = re.compile(
    r"""(\w[\w.\-]*)=(?:"([^"]*?)"|'([^']*?)'|(\S+))""",
)


def parse_kv_events(text: str) -> list[dict]:
    """Parse key=value log lines into a list of dicts.

    Each non-empty line is treated as one event.
    Supports: key=value, key="quoted value", key='quoted value'.
    """
    text = text.strip()
    if not text:
        return []

    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        pairs = _KV_PATTERN.findall(line)
        if not pairs:
            continue
        record: dict[str, str] = {}
        for key, dq_val, sq_val, plain_val in pairs:
            record[key] = dq_val or sq_val or plain_val
        if record:
            events.append(record)

    return events


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_and_parse(text: str) -> list[dict] | None:
    """Try non-JSON formats in order. Returns list of dicts or None if no match.

    Detection order:
    1. Windows Event XML (starts with <Event or <?xml)
    2. CSV/TSV (header line with commas/tabs, at least 2 lines)
    3. Key=Value (lines with key=value patterns)
    """
    stripped = text.strip()
    if not stripped:
        return None

    # 1. Windows Event XML
    if stripped.startswith("<Event") or stripped.startswith("<?xml") or stripped.startswith("<Events"):
        result = parse_xml_events(stripped)
        if result:
            return result

    # 2. CSV/TSV — heuristic: first line has multiple commas or tabs, and >=2 lines
    lines = stripped.splitlines()
    if len(lines) >= 2:
        first = lines[0]
        comma_count = first.count(",")
        tab_count = first.count("\t")
        # If the header has 2+ delimiters and doesn't look like JSON/XML/KV
        if (comma_count >= 2 or tab_count >= 2) and not first.startswith(("{", "[", "<")):
            # Extra check: header shouldn't have = signs (that'd be KV)
            if "=" not in first or comma_count > first.count("="):
                result = parse_csv_events(stripped)
                if result:
                    return result

    # 3. Key=Value
    if "=" in stripped:
        result = parse_kv_events(stripped)
        if result:
            return result

    return None
