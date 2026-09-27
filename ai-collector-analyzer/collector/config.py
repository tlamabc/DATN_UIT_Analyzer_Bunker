"""Environment-backed collector configuration and shared constants."""
import logging
import os
from datetime import timedelta, timezone
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("ai_collector")
RISK_LEVELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
SECURITY_STATUSES = {403, 406, 429}

def positive_int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        return max(minimum, int(raw))
    except (TypeError, ValueError):
        LOGGER.warning("Invalid %s=%r; using default %d", name, raw, default)
        return default

def analyzer_timezone():
    # Vietnam has a fixed UTC+07:00 offset; this avoids depending on OS tzdata in slim images.
    return timezone(timedelta(hours=7), name="Asia/Ho_Chi_Minh")
