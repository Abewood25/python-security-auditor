
import json
import subprocess

from defender_security import (
    get_defender_status,
    audit_defender_status
)


def main():
    print("\n=== MICROSOFT DEFENDER SECURITY AUDIT ===")

    try:
        status = get_defender_status()

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
        json.JSONDecodeError,
        ValueError
    ) as error:
        print(f"Unable to collect Defender status: {error}")
        return

    print("\nDefender Security Status:")

    for setting, value in status.items():
        print(f"{setting}: {value}")

    findings = audit_defender_status(status)

    print(f"\nTotal security findings: {len(findings)}")

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['issue']}")
        print(f"Recommendation: {finding['recommendation']}")

    report = {
        "scan_type": "Microsoft Defender Security Audit",
        "status": status,
        "findings": findings
    }

    with open("defender_security_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReport saved to defender_security_report.json")


if __name__ == "__main__":
    main()
