
from pathlib import Path


def generate_markdown_report(report):
    """Convert a security assessment into a Markdown report."""

    summary = report["summary"]
    findings = report["findings"]

    lines = [
        "# Windows Security Posture Assessment",
        "",
        "## Executive Summary",
        "",
        f"**Assessment Date:** {report['timestamp']}",
        "",
        f"**Overall Risk Level:** {report['risk_level']}",
        "",
        f"**Risk Score:** {report['risk_score']}",
        "",
        f"**Total Findings:** {report['total_findings']}",
        "",
        "## Security Findings Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| HIGH | {summary['HIGH']} |",
        f"| MEDIUM | {summary['MEDIUM']} |",
        f"| LOW | {summary['LOW']} |",
        "",
        "## Assessment Scope",
        "",
        "- Windows Firewall configuration",
        "- Microsoft Defender Antivirus status",
        "- Windows Update hotfix history",
        "",
        "## Detailed Findings",
        ""
    ]

    if not findings:
        lines.extend([
            "No security findings were detected by the configured checks.",
            ""
        ])

    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### Finding {index}: {finding['issue']}",
            "",
            f"**Severity:** {finding['severity']}",
            "",
            f"**Recommendation:** {finding['recommendation']}",
            ""
        ])

    lines.extend([
        "## Assessment Limitations",
        "",
        "- This tool performs selected configuration checks.",
        "- A low risk score does not guarantee system security.",
        "- Hotfix history does not prove all patches are installed.",
        "",
        "## Conclusion",
        "",
        "Review identified findings and validate remediation.",
        ""
    ])

    return "\n".join(lines)


def save_markdown_report(report, output_path):
    """Save a Markdown security report."""

    content = generate_markdown_report(report)

    Path(output_path).write_text(
        content,
        encoding="utf-8"
    )

    return output_path
