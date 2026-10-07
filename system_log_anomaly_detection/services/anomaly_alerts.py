"""Detection helpers for high-volume anomaly alerts."""

import pandas as pd


def find_anomaly_burst(
    events: pd.DataFrame,
    threshold: int,
    window_minutes: int,
) -> tuple[int, pd.Timestamp, pd.Timestamp] | None:
    """Return the densest anomaly interval meeting the threshold, if any."""
    if threshold < 1 or window_minutes < 1 or events.empty:
        return None

    anomalies = events.loc[events["status"] == "ANOMALY", ["timestamp"]].copy()
    if anomalies.empty:
        return None

    anomalies["timestamp"] = pd.to_datetime(anomalies["timestamp"], errors="coerce")
    timestamps = anomalies["timestamp"].dropna().sort_values().reset_index(drop=True)
    if timestamps.empty:
        return None

    window = pd.Timedelta(minutes=window_minutes)
    left = 0
    best: tuple[int, pd.Timestamp, pd.Timestamp] | None = None
    for right, end in enumerate(timestamps):
        while end - timestamps.iloc[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold and (best is None or count > best[0]):
            best = (count, timestamps.iloc[left], end)
    return best
