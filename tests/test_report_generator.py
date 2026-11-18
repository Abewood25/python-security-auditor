
from report_generator import (
    generate_markdown_report,
    save_markdown_report
)


def sample_report():
    return {
        "timestamp": "2026-11-15T12:00:00+00:00",
        "risk_level": "HIGH",
        "risk_score": 20,
        "total_findings": 2,
        "summary": {
            "HIGH": 2,
            "MEDIUM": 0,
            "LOW": 0
        },
        "findings": [
            {
                "severity": "HIGH",
                "issue": "Public firewall profile is disabled",
                "recommendation": "Enable the Public firewall."
            },
            {
                "severity": "HIGH",
                "issue": "Real-time antivirus protection is disabled",
                "recommendation": "Enable approved real-time protection."
            }
        ]
    }


def test_report_contains_executive_summary():
    markdown = generate_markdown_report(sample_report())

    assert "Executive Summary" in markdown
    assert "Risk Score" in markdown


def test_report_contains_security_findings():
    markdown = generate_markdown_report(sample_report())

    assert "Public firewall profile is disabled" in markdown
    assert "Real-time antivirus protection is disabled" in markdown


def test_report_contains_recommendations():
    markdown = generate_markdown_report(sample_report())

    assert "Enable the Public firewall." in markdown
    assert "Enable approved real-time protection." in markdown


def test_report_without_findings():
    report = sample_report()
    report["findings"] = []
    report["total_findings"] = 0
    report["risk_score"] = 0
    report["risk_level"] = "LOW"
    report["summary"] = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    markdown = generate_markdown_report(report)

    assert "No security findings were detected" in markdown


def test_save_markdown_report(tmp_path):
    output = tmp_path / "security_report.md"

    save_markdown_report(sample_report(), output)

    assert output.exists()
    assert "Executive Summary" in output.read_text(
        encoding="utf-8"
    )
