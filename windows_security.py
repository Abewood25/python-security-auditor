
import json
import subprocess


def get_firewall_profiles():
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-NetFirewallProfile | "
            "Select-Object Name, Enabled | "
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

    profiles = json.loads(result.stdout)

    if isinstance(profiles, dict):
        profiles = [profiles]

    return profiles


def audit_firewall_profiles(profiles):
    findings = []

    for profile in profiles:
        if profile["Enabled"] is False:
            findings.append({
                "severity": "HIGH",
                "issue": f"{profile['Name']} firewall profile is disabled",
                "recommendation": (
                    f"Review and enable the {profile['Name']} "
                    "firewall profile if required by policy."
                )
            })

    return findings
