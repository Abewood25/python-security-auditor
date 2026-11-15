
import json
import subprocess
from datetime import datetime, timezone

from full_security_audit import (
    collect_security_data,
    build_security_report
)


def main():
    print("\n=== WINDOWS SECURITY POSTURE ASSESSMENT ===")

    try:
        (
            firewall_profiles,
            defender_status,
            windows_updates
        ) = collect_security_data()

        report = build_security_report(
            firewall_profiles,
            defender_status,
            scan_time=datetime.now(timezone.utc),
            windows_updates=windows_updates
        )

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
        json.JSONDecodeError,
        ValueError,
        KeyError,
        TypeError
    ) as error:
        print(f"\nSecurity audit failed: {error}")
        return

    print("\n=== SECURITY SUMMARY ===")
    print(f"Total findings: {report['total_findings']}")
    print(f"High severity: {report['summary']['HIGH']}")
    print(f"Medium severity: {report['summary']['MEDIUM']}")
    print(f"Low severity: {report['summary']['LOW']}")
    print(f"Risk score: {report['risk_score']}")
    print(f"Risk level: {report['risk_level']}")

    print("\n=== SECURITY MODULES ===")
    print("Windows Firewall: Assessed")
    print("Microsoft Defender: Assessed")
    print(
        "Windows Update: "
        f"{report['windows_update_status']}"
    )

    print("\n=== SECURITY FINDINGS ===")

    if not report["findings"]:
        print("No findings detected by the configured checks.")

    for finding in report["findings"]:
        print(f"\n[{finding['severity']}] {finding['issue']}")
        print(f"Recommendation: {finding['recommendation']}")

    with open(
        "full_security_report.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(report, file, indent=4)

    print("\nReport saved to full_security_report.json")


if __name__ == "__main__":
    main()
