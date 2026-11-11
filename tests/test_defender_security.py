
from datetime import datetime, timedelta, timezone

from defender_security import audit_defender_status


def healthy_status():
    return {
        "AMServiceEnabled": True,
        "AntivirusEnabled": True,
        "RealTimeProtectionEnabled": True,
        "AntivirusSignatureLastUpdated": "2026-11-08T12:00:00Z"
    }


def test_healthy_defender():
    status = healthy_status()
    now = datetime(2026, 11, 8, 13, tzinfo=timezone.utc)

    findings = audit_defender_status(status, now=now)

    assert len(findings) == 0


def test_antivirus_disabled():
    status = healthy_status()
    status["AntivirusEnabled"] = False

    findings = audit_defender_status(
        status,
        now=datetime(2026, 11, 8, 13, tzinfo=timezone.utc)
    )

    assert any(
        f["issue"] == "Microsoft Defender Antivirus is disabled"
        for f in findings
    )


def test_real_time_protection_disabled():
    status = healthy_status()
    status["RealTimeProtectionEnabled"] = False

    findings = audit_defender_status(
        status,
        now=datetime(2026, 11, 8, 13, tzinfo=timezone.utc)
    )

    assert any(
        f["issue"] == "Real-time antivirus protection is disabled"
        for f in findings
    )


def test_outdated_signatures():
    now = datetime(2026, 11, 8, 13, tzinfo=timezone.utc)
    status = healthy_status()

    old_date = now - timedelta(days=10)
    status["AntivirusSignatureLastUpdated"] = old_date.isoformat()

    findings = audit_defender_status(status, now=now)

    assert any(
        "more than 7 days old" in f["issue"]
        for f in findings
    )

