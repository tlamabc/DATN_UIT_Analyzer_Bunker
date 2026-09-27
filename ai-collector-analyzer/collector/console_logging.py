"""Persist collector records for the live dashboard console."""
import logging

from .database import save_console_log


class PostgresConsoleHandler(logging.Handler):
    """Write log records to PostgreSQL without breaking collection on DB errors."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            save_console_log(record.levelname, record.name, self.format(record))
        except Exception:
            # Logging must never recurse or terminate the analyzer when persistence fails.
            self.handleError(record)
