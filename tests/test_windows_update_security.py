
from datetime import datetime, timezone

from windows_update_security import audit_windows_updates


TEST_TIME = datetime(
    2026, 11, 15, 12, tzinfo=timezone.utc
)


def test_recent_updates():
    updates = [
        {
            "HotFixID": "KB1234567",
            "InstalledOn": "2026-11-10"
        }
    ]

    findings = audit_windows_updates(
        updates, now=TEST_TIME
    )

    assert len(findings) == 0


def test_old_updates():
    updates = [
        {
            "HotFixID": "KB1234567",
            "InstalledOn": "2026-08-01"
        }
    ]

    findings = audit_windows_updates(
        updates, now=TEST_TIME
    )

    assert any(
        "45 days" in finding["issue"]
        for finding in findings
    )


def test_no_update_records():
    findings = audit_windows_updates(
        [], now=TEST_TIME
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_invalid_update_dates():
    updates = [
        {
            "HotFixID": "KB1234567",
            "InstalledOn": "invalid-date"
        }
    ]

    findings = audit_windows_updates(
        updates, now=TEST_TIME
    )

    assert any(
        "dates are unavailable" in finding["issue"]
        for finding in findings
    )
