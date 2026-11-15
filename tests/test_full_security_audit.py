
from datetime import datetime, timezone

from full_security_audit import build_security_report


TEST_TIME = datetime(
    2026, 11, 10, 12, 0, tzinfo=timezone.utc
)


def healthy_firewall():
    return [
        {"Name": "Domain", "Enabled": True},
        {"Name": "Private", "Enabled": True},
        {"Name": "Public", "Enabled": True}
    ]


def healthy_defender():
    return {
        "AMServiceEnabled": True,
        "AntivirusEnabled": True,
        "RealTimeProtectionEnabled": True,
        "AntivirusSignatureLastUpdated": "2026-11-10T11:00:00Z"
    }


def test_healthy_security_posture():
    report = build_security_report(
        healthy_firewall(),
        healthy_defender(),
        scan_time=TEST_TIME
    )

    assert report["total_findings"] == 0
    assert report["risk_score"] == 0
    assert report["risk_level"] == "LOW"


def test_disabled_firewall_increases_risk():
    firewall = healthy_firewall()
    firewall[2]["Enabled"] = False

    report = build_security_report(
        firewall,
        healthy_defender(),
        scan_time=TEST_TIME
    )

    assert report["total_findings"] == 1
    assert report["risk_score"] == 10
    assert report["summary"]["HIGH"] == 1


def test_multiple_security_weaknesses():
    firewall = healthy_firewall()
    firewall[2]["Enabled"] = False

    defender = healthy_defender()
    defender["AntivirusEnabled"] = False
    defender["RealTimeProtectionEnabled"] = False

    report = build_security_report(
        firewall,
        defender,
        scan_time=TEST_TIME
    )

    assert report["total_findings"] == 3
    assert report["risk_score"] == 30
    assert report["risk_level"] == "CRITICAL"


def test_report_contains_security_evidence():
    report = build_security_report(
        healthy_firewall(),
        healthy_defender(),
        scan_time=TEST_TIME
    )

    assert "firewall_profiles" in report
    assert "defender_status" in report
    assert "findings" in report
    assert "timestamp" in report
