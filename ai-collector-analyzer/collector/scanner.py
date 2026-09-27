"""Bounded, resumable scanning of security log entries."""
import logging
from datetime import datetime
from pathlib import Path
from .config import LOGGER
from .database import save_event, save_offset
from .log_parser import event_timestamp, is_security_event, parse_log
from .vmaas import analyze_log

def scan_file(path: Path, offset: int, cutoff: datetime, event_budget: int, line_budget: int,
              response_language: str) -> tuple[int, int, int, str | None]:
    analyzed = 0
    lines_read = 0
    last_error = None
    try:
        if path.stat().st_size < offset:
            offset = 0
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            stream.seek(offset)
            while event_budget > 0 and line_budget > 0 and (line := stream.readline()):
                lines_read += 1
                line_budget -= 1
                line_start, current = offset, stream.tell()
                raw = line.strip()
                if not raw:
                    offset = current
                    continue
                data = parse_log(raw)
                timestamp = event_timestamp(data)
                if timestamp is None or timestamp < cutoff or not is_security_event(data, raw):
                    offset = current
                    continue
                try:
                    result, usage = analyze_log(raw, data, response_language)
                    save_event(raw, data, result, usage)
                    LOGGER.info("Analyzed security event from %s", path.name)
                    offset = current
                    analyzed += 1
                    event_budget -= 1
                except Exception:
                    offset = line_start
                    last_error = "vMaaS analysis failed; retrying this log entry on the next scan"
                    LOGGER.exception("Analyzer failed for %s; this line will retry next scan", path.name)
                    break
    except FileNotFoundError:
        return offset, analyzed, lines_read, f"Log file not found: {path}"
    except PermissionError:
        LOGGER.error("Permission denied reading %s", path)
        return offset, analyzed, lines_read, f"Permission denied reading {path}"
    save_offset(str(path), offset)
    return offset, analyzed, lines_read, last_error
