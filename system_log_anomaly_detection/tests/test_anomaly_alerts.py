import pandas as pd

from services.anomaly_alerts import find_anomaly_burst


def test_finds_anomaly_burst_within_window():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-01-01 00:00:00",
            "2026-01-01 00:01:00",
            "2026-01-01 00:04:00",
            "2026-01-01 00:20:00",
        ]),
        "status": ["ANOMALY", "ANOMALY", "ANOMALY", "ANOMALY"],
    })

    assert find_anomaly_burst(events, threshold=3, window_minutes=5) == (
        3,
        pd.Timestamp("2026-01-01 00:00:00"),
        pd.Timestamp("2026-01-01 00:04:00"),
    )


def test_ignores_normal_events_and_anomalies_outside_window():
    events = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-01-01 00:00:00",
            "2026-01-01 00:01:00",
            "2026-01-01 00:20:00",
        ]),
        "status": ["ANOMALY", "NORMAL", "ANOMALY"],
    })

    assert find_anomaly_burst(events, threshold=2, window_minutes=5) is None


def test_returns_no_burst_for_invalid_settings_or_missing_timestamps():
    events = pd.DataFrame({
        "timestamp": ["not a timestamp"],
        "status": ["ANOMALY"],
    })

    assert find_anomaly_burst(events, threshold=0, window_minutes=5) is None
    assert find_anomaly_burst(events, threshold=1, window_minutes=5) is None
