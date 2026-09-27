"""Security-oriented aggregations derived from analyzed BunkerWeb events."""
import pandas as pd


def suspicious_ip_candidates(events: pd.DataFrame) -> pd.DataFrame:
    """Rank IPs for review by repeated security hits or high-severity events.

    This is a triage heuristic; it does not assert that an IP is malicious.
    """
    columns = ["client_ip", "event_count", "high_critical", "attack_types", "review_reason", "last_seen"]
    if events.empty or "client_ip" not in events:
        return pd.DataFrame(columns=columns)

    candidates = events.dropna(subset=["client_ip"]).copy()
    candidates["client_ip"] = candidates["client_ip"].astype(str).str.strip()
    candidates = candidates[candidates["client_ip"] != ""]
    if candidates.empty:
        return pd.DataFrame(columns=columns)

    candidates["high_critical_flag"] = candidates["severity"].astype(str).str.lower().isin({"high", "critical"})
    summary = candidates.groupby("client_ip", as_index=False).agg(
        event_count=("id", "count"),
        high_critical=("high_critical_flag", "sum"),
        attack_types=("attack_type", "nunique"),
        last_seen=("timestamp", "max"),
    )
    summary = summary[(summary["event_count"] >= 3) | (summary["high_critical"] > 0)]
    summary["review_reason"] = summary.apply(
        lambda row: "Repeated hits + High/Critical" if row["event_count"] >= 3 and row["high_critical"] > 0
        else ("Repeated hits" if row["event_count"] >= 3 else "High/Critical event"), axis=1,
    )
    return summary.sort_values(["high_critical", "event_count", "last_seen"], ascending=False).head(20)[columns]
