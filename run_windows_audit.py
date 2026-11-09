
import json
import subprocess

from windows_security import (
    get_firewall_profiles,
    audit_firewall_profiles
)


def main():
    print("\n=== REAL WINDOWS SECURITY AUDIT ===")

    try:
        profiles = get_firewall_profiles()

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
        json.JSONDecodeError
    ) as error:
        print(f"Unable to collect firewall settings: {error}")
        return

    if not profiles:
        print("No firewall profiles were returned.")
        return

    print("\nWindows Firewall Profiles:")

    for profile in profiles:
        print(
            f"{profile['Name']}: "
            f"Enabled = {profile['Enabled']}"
        )

    findings = audit_firewall_profiles(profiles)

    print(f"\nSecurity findings: {len(findings)}")

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['issue']}")
        print(f"Recommendation: {finding['recommendation']}")

    report = {
        "scan_type": "Windows Firewall Configuration",
        "profiles": profiles,
        "findings": findings
    }

    with open("windows_security_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReport saved to windows_security_report.json")


if __name__ == "__main__":
    main()
