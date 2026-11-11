
import json
import subprocess
from datetime import datetime, timezone


def get_defender_status():
    """Collect Microsoft Defender status without changing settings."""

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-MpComputerStatus | "
            "Select-Object AMServiceEnabled, AntivirusEnabled, "
            "RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | "
            "ConvertTo-Json -Compress"
        )
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=True
    )

    if not result.stdout.strip():
        raise ValueError("No Microsoft Defender status was returned.")

    status = json.loads(result.stdout)

    if not isinstance(status, dict):
        raise ValueError("Unexpected Microsoft Defender response.")

    return status


def audit_defender_status(status, now=None):
    """Analyze Defender settings and return security findings."""

    findings = []

    def add_finding(severity, issue, recommendation):
        findings.append({
            "severity": severity,
            "issue": issue,
            "recommendation": recommendation
        })

    if status.get("AMServiceEnabled") is False:
        add_finding(
            "HIGH",
            "Microsoft Defender antivirus service is disabled",
            "Review the antivirus service and endpoint protection."
        )

    if status.get("AntivirusEnabled") is False:
        add_finding(
            "HIGH",
            "Microsoft Defender Antivirus is disabled",
            "Verify that approved antivirus protection is active."
        )

    if status.get("RealTimeProtectionEnabled") is False:
        add_finding(
            "HIGH",
            "Real-time antivirus protection is disabled",
            "Review and enable approved real-time protection."
        )

    signature_date = status.get("AntivirusSignatureLastUpdated")

    if signature_date:
        try:
            # PowerShell JSON dates may use /Date(milliseconds)/.
            if isinstance(signature_date, str) and signature_date.startswith("/Date("):
                milliseconds = int(
                    signature_date.split("(")[1].split(")")[0]
                    .split("+")[0].split("-")[0]
                )
                updated = datetime.fromtimestamp(
                    milliseconds / 1000, tz=timezone.utc
                )
            else:
                updated = datetime.fromisoformat(
                    signature_date.replace("Z", "+00:00")
                )
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)

            current = now or datetime.now(timezone.utc)
            age_days = (current - updated).total_seconds() / 86400

            if age_days > 7:
                add_finding(
                    "MEDIUM",
                    "Antivirus signatures are more than 7 days old",
                    "Check antivirus definition updates."
                )

        except (ValueError, TypeError, OverflowError):
            add_finding(
                "MEDIUM",
                "Unable to interpret antivirus signature date",
                "Verify the antivirus signature update status."
            )
    else:
        add_finding(
            "MEDIUM",
            "Antivirus signature update date is unavailable",
            "Verify antivirus definition status."
        )

    return findings
