
from datetime import datetime, timezone

from windows_security import (
    get_firewall_profiles,
    audit_firewall_profiles
)
from defender_security import (
    get_defender_status,
    audit_defender_status
)
from risk_scoring import (
    calculate_risk_score,
    summarize_findings,
    determine_risk_level
)


def build_security_report(
    firewall_profiles,
    defender_status,
    scan_time=None
):
    """Analyze collected security data and build one report."""

    firewall_findings = audit_firewall_profiles(
        firewall_profiles
    )

    defender_findings = audit_defender_status(
        defender_status,
        now=scan_time
    )

    findings = firewall_findings + defender_findings

    score = calculate_risk_score(findings)
    summary = summarize_findings(findings)
    risk_level = determine_risk_level(score)

    timestamp = scan_time or datetime.now(timezone.utc)

    return {
        "scan_type": "Windows Security Posture Assessment",
        "timestamp": timestamp.isoformat(),
        "risk_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "total_findings": len(findings),
        "firewall_profiles": firewall_profiles,
        "defender_status": defender_status,
        "findings": findings
    }


def collect_security_data():
    """Collect actual Windows security settings."""

    firewall_profiles = get_firewall_profiles()
    defender_status = get_defender_status()

    return firewall_profiles, defender_status
