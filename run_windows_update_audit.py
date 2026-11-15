
import json
import subprocess

from windows_update_security import (
    get_windows_updates,
    audit_windows_updates
)


def main():
    print("\n=== WINDOWS UPDATE SECURITY AUDIT ===")

    try:
        updates = get_windows_updates()

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
        json.JSONDecodeError,
        ValueError
    ) as error:
        print(f"Unable to collect update history: {error}")
        return

    print(f"\nInstalled hotfix records returned: {len(updates)}")

    for update in updates:
        print(
            f"{update.get('HotFixID')}: "
            f"{update.get('InstalledOn')}"
        )

    findings = audit_windows_updates(updates)

    print(f"\nTotal findings: {len(findings)}")

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['issue']}")
        print(f"Recommendation: {finding['recommendation']}")

    report = {
        "scan_type": "Windows Update History Audit",
        "updates": updates,
        "findings": findings
    }

    with open(
        "windows_update_report.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(report, file, indent=4)

    print("\nReport saved to windows_update_report.json")


if __name__ == "__main__":
    main()
