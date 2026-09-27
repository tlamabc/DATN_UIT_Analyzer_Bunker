"""Dashboard environment and timezone configuration."""
import os
from datetime import timedelta, timezone
from dotenv import load_dotenv
load_dotenv()
APP_TZ = timezone(timedelta(hours=7), name="Asia/Ho_Chi_Minh")
DB_DEFAULTS = {"host": os.getenv("DB_HOST", "postgres_db"), "port": int(os.getenv("DB_PORT", "5432")),
    "user": os.getenv("DB_USER", "security"), "password": os.getenv("DB_PASSWORD", ""),
    "dbname": os.getenv("DB_NAME", "security_events"), "connect_timeout": 8}

def safe_int_env(name: str, default: int = 0) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default
