
from auditor import audit_configuration
from risk_scoring import (
    calculate_risk_score,
    summarize_findings,
    determine_risk_level
)


def secure_config():
    return {
        "hostname": "SECURE-SERVER",
        "firewall_enabled": True,
        "antivirus_enabled": True,
        "automatic_updates": True,
        "guest_account_enabled": False,
        "minimum_password_length": 14,
        "unnecessary_services": []
    }


def test_secure_configuration():
    findings = audit_configuration(secure_config())

    assert len(findings) == 0


def test_disabled_firewall():
    config = secure_config()
    config["firewall_enabled"] = False

    findings = audit_configuration(config)

    assert any(
        finding["issue"] == "Firewall is disabled"
        for finding in findings
    )


def test_weak_password_policy():
    config = secure_config()
    config["minimum_password_length"] = 6

    findings = audit_configuration(config)

    assert any(
        finding["issue"] == "Minimum password length is below 12"
        for finding in findings
    )


def test_risk_scoring():
    findings = [
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "MEDIUM"}
    ]

    score = calculate_risk_score(findings)

    assert score == 20
    assert determine_risk_level(score) == "HIGH"


def test_findings_summary():
    findings = [
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"}
    ]

    summary = summarize_findings(findings)

    assert summary["HIGH"] == 1
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1
