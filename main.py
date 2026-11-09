
import json

from auditor import audit_configuration
from risk_scoring import (
    calculate_risk_score,
    summarize_findings,
    determine_risk_level
)


def main():
    with open("sample_config.json", "r", encoding="utf-8") as file:
        config = json.load(file)

    with open("security_policy.json", "r", encoding="utf-8") as file:
        policy = json.load(file)

    findings = audit_configuration(config, policy)

    score = calculate_risk_score(findings)
    summary = summarize_findings(findings)
    risk_level = determine_risk_level(score)

    print("\n=== SECURITY CONFIGURATION AUDITOR ===")
    print(f"Host: {config['hostname']}")
    print(f"Total findings: {len(findings)}")

    print("\n=== SECURITY SUMMARY ===")
    print(f"High findings: {summary['HIGH']}")
    print(f"Medium findings: {summary['MEDIUM']}")
    print(f"Low findings: {summary['LOW']}")
    print(f"Risk score: {score}")
    print(f"Overall risk level: {risk_level}")

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['issue']}")
        print(f"Recommendation: {finding['recommendation']}")

    report = {
        "hostname": config["hostname"],
        "risk_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "findings": findings
    }

    with open("security_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReport saved to security_report.json")


if __name__ == "__main__":
    main()
