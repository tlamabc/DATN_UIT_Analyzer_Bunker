"""Dashboard-controlled analyzer polling and scheduled scan service."""
import glob
import logging
import os
import time
from datetime import date, datetime, time as datetime_time
from pathlib import Path
from .config import LOGGER, analyzer_timezone, positive_int_env
from .console_logging import PostgresConsoleHandler
from .database import (clear_reset_request, db_connect, get_control, initialize_database,
                       load_offsets, load_waf_offsets, update_progress)
from .scanner import scan_file, scan_waf_observations

def main() -> None:
    log_glob = os.getenv("BUNKERWEB_LOG_GLOB", "/var/log/bunkerweb/access.log")
    interval = positive_int_env("ANALYZER_SCAN_INTERVAL_SECONDS", 600)
    max_events = positive_int_env("ANALYZER_MAX_EVENTS_PER_SCAN", 3)
    max_lines = positive_int_env("ANALYZER_MAX_LINES_PER_SCAN", 2000)
    poll_seconds = positive_int_env("ANALYZER_CONTROL_POLL_SECONDS", 5)
    tz = analyzer_timezone()
    initialize_database()
    console_handler = PostgresConsoleHandler()
    console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(console_handler)
    offsets = load_offsets()
    waf_offsets = load_waf_offsets()
    next_scan_at = 0.0
    active_scan_date: date | None = None
    LOGGER.info("Analyzer idle; start it from the dashboard. Log source: %s", log_glob)
    while True:
        try:
            current_date = datetime.now(tz).date()
            observation_cutoff = datetime.combine(current_date, datetime_time.min, tzinfo=tz)
            for filename in sorted(glob.glob(log_glob)):
                if not Path(filename).name.startswith("access.log"):
                    continue
                saved_offset, generation = waf_offsets.get(filename, (0, 0))
                observation_offset, generation, _ = scan_waf_observations(
                    Path(filename), saved_offset, generation, observation_cutoff, max_lines
                )
                waf_offsets[filename] = (observation_offset, generation)

            enabled, scan_date, reset_requested, response_language = get_control()
            if reset_requested:
                offsets.clear()
                clear_reset_request()
                next_scan_at = 0.0
                update_progress("Starting", None, 0, error=None)
                LOGGER.info("Analyzer cursor reset; scanning from 00:00 %s", scan_date.isoformat())
            today = datetime.now(tz).date()
            if enabled and scan_date != today:
                scan_date = today
                offsets.clear()
                with db_connect() as conn, conn.cursor() as cur:
                    cur.execute("UPDATE analyzer_control SET scan_date=%s WHERE id=1", (today,))
                    cur.execute("DELETE FROM collector_offsets")
                    cur.execute("UPDATE analyzer_control SET progress_percent=0, scanned_lines=0, events_analyzed=0, last_error=NULL WHERE id=1")
                next_scan_at = 0.0
            if enabled and time.monotonic() >= next_scan_at:
                cutoff = datetime.combine(scan_date, datetime_time.min, tzinfo=tz)
                budget = max_events
                line_budget = max_lines
                total = 0
                last_error = None
                current_file = None
                for filename in sorted(glob.glob(log_glob)):
                    if budget <= 0 or line_budget <= 0:
                        break
                    path = Path(filename)
                    current_file = filename
                    current_offset = offsets.get(filename, 0)
                    try:
                        size = path.stat().st_size
                    except OSError:
                        size = 0
                    update_progress("Scanning", filename, (100.0 * current_offset / size) if size else 0.0)
                    offset, count, lines_read, file_error = scan_file(
                        path, current_offset, cutoff, budget, line_budget, response_language
                    )
                    offsets[filename] = offset
                    total += count
                    budget -= count
                    line_budget -= lines_read
                    last_error = file_error or last_error
                    try:
                        size_after = path.stat().st_size
                    except OSError:
                        size_after = 0
                    percent = (100.0 * offset / size_after) if size_after else 0.0
                    state = "Error" if file_error else ("Waiting" if offset >= size_after else "Scanning")
                    update_progress(state, filename, percent, lines_read, count, file_error)
                    if file_error:
                        break
                if not current_file:
                    update_progress("Waiting", None, 0, error="Configured BunkerWeb log file was not found")
                LOGGER.info("Scheduled scan complete: %d security event(s) sent to vMaaS", total)
                active_scan_date = scan_date
                next_scan_at = time.monotonic() + interval
            elif not enabled and active_scan_date is not None:
                LOGGER.info("Analyzer stopped from dashboard")
                active_scan_date = None
                next_scan_at = 0.0
        except Exception:
            LOGGER.exception("Analyzer control/scan iteration failed")
        time.sleep(poll_seconds)
