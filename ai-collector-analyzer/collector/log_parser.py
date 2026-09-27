"""Parse BunkerWeb JSON and combined access log records."""
import json
import re
from datetime import datetime
from typing import Any
from .config import SECURITY_STATUSES, analyzer_timezone

ACCESS_TIME_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
ACCESS_STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,}\b")

def parse_log(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
        if isinstance(value, dict):
            value.setdefault("message", raw)
            return value
    except json.JSONDecodeError:
        pass
    ip_match = IP_RE.search(raw)
    time_match = ACCESS_TIME_RE.search(raw)
    status_match = ACCESS_STATUS_RE.search(raw)
    parsed: dict[str, Any] = {"message": raw}
    if ip_match:
        parsed["client_ip"] = ip_match.group(0)
    if time_match:
        try:
            parsed["timestamp"] = datetime.strptime(time_match.group(1), "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except ValueError:
            pass
    if status_match:
        parsed["status"] = int(status_match.group(1))
    return parsed

def event_timestamp(data: dict[str, Any]) -> datetime | None:
    value = data.get("timestamp") or data.get("time")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=analyzer_timezone())
        return parsed
    except ValueError:
        return None

def is_security_event(data: dict[str, Any], raw: str) -> bool:
    for key in ("status", "status_code", "http_status", "response_code"):
        try:
            if int(data.get(key, 0)) in SECURITY_STATUSES:
                return True
        except (TypeError, ValueError):
            continue
    if data.get("blocked") is True or data.get("security_event") is True:
        return True
    return bool(re.search(r"\b(modsecurity|waf blocked|blocked by rule|attack detected)\b", raw, re.I))

