
from datetime import datetime, timezone

from windows_security import (
    get_firewall_profiles,
    audit_firewall_profiles
)
from defender_security import (
    get_defender_status,
    audit_defender_status
)
from windows_update_security import (
    get_windows_updates,
    audit_windows_updates
)
from risk_scoring import (
    calculate_risk_score,
    summarize_findings,
    determine_risk_level
)


def build_security_report(
    firewall_profiles,
    defender_status,
    scan_time=None,
    windows_updates=None
):
    """Build a consolidated Windows security report."""

    timestamp = scan_time or datetime.now(timezone.utc)

    firewall_findings = audit_firewall_profiles(
        firewall_profiles
    )

    defender_findings = audit_defender_status(
        defender_status,
        now=timestamp
    )

    # None means update data was not supplied.
    # An empty list means collection returned no records.
    if windows_updates is None:
        update_findings = []
        update_status = "NOT_ASSESSED"
    else:
        update_findings = audit_windows_updates(
            windows_updates,
            now=timestamp
        )
        update_status = "ASSESSED"

    findings = (
        firewall_findings
        + defender_findings
        + update_findings
    )

    score = calculate_risk_score(findings)
    summary = summarize_findings(findings)
    risk_level = determine_risk_level(score)

    return {
        "scan_type": "Windows Security Posture Assessment",
        "timestamp": timestamp.isoformat(),
        "risk_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "total_findings": len(findings),
        "firewall_profiles": firewall_profiles,
        "defender_status": defender_status,
        "windows_update_status": update_status,
        "windows_updates": windows_updates,
        "findings": findings
    }


def collect_security_data():
    """Collect real Windows security settings."""

    firewall_profiles = get_firewall_profiles()
    defender_status = get_defender_status()
    windows_updates = get_windows_updates()

    return firewall_profiles, defender_status, windows_updates
