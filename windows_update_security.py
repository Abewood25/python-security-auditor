
import json
import subprocess
from datetime import datetime, timezone


def get_windows_updates():
    """Collect installed Windows hotfix information."""

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-HotFix | "
            "Sort-Object InstalledOn -Descending | "
            "Select-Object -First 10 HotFixID, Description, "
            "@{Name='InstalledOn';Expression={"
            "if ($_.InstalledOn) { "
            "$_.InstalledOn.ToString('yyyy-MM-dd') "
            "} else { $null }"
            "}} | ConvertTo-Json -Compress"
        )
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=45,
        check=True
    )

    if not result.stdout.strip():
        return []

    updates = json.loads(result.stdout)

    if isinstance(updates, dict):
        updates = [updates]

    if not isinstance(updates, list):
        raise ValueError("Unexpected Windows Update response.")

    return updates


def audit_windows_updates(updates, now=None):
    """Evaluate update-history visibility and age."""

    findings = []
    current = now or datetime.now(timezone.utc)

    if not updates:
        findings.append({
            "severity": "MEDIUM",
            "issue": "No installed hotfix records were returned",
            "recommendation":
                "Verify Windows Update history and collection access."
        })
        return findings

    dates = []

    for update in updates:
        date_string = update.get("InstalledOn")

        if date_string:
            try:
                date = datetime.strptime(
                    date_string, "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
                dates.append(date)
            except (ValueError, TypeError):
                continue

    if not dates:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Installed update dates are unavailable",
            "recommendation":
                "Verify Windows Update history manually."
        })
        return findings

    latest = max(dates)
    age_days = (current - latest).total_seconds() / 86400

    if age_days > 45:
        findings.append({
            "severity": "MEDIUM",
            "issue": "No reported hotfix installation in 45 days",
            "recommendation":
                "Review Windows Update status and pending updates."
        })

    return findings
