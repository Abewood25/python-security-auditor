
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


def test_mfa_disabled():
    config = secure_config()
    config["mfa_enabled"] = False

    policy = {
        "minimum_password_length": 12,
        "require_firewall": True,
        "require_antivirus": True,
        "require_automatic_updates": True,
        "require_mfa": True,
        "require_disk_encryption": False,
        "allow_remote_desktop": True,
        "allow_guest_account": False
    }

    findings = audit_configuration(config, policy)

    assert any(
        finding["issue"] == "Multi-factor authentication is disabled"
        for finding in findings
    )


def test_disk_encryption_disabled():
    config = secure_config()
    config["disk_encryption_enabled"] = False

    policy = {
        "minimum_password_length": 12,
        "require_firewall": True,
        "require_antivirus": True,
        "require_automatic_updates": True,
        "require_mfa": False,
        "require_disk_encryption": True,
        "allow_remote_desktop": True,
        "allow_guest_account": False
    }

    findings = audit_configuration(config, policy)

    assert any(
        finding["issue"] == "Disk encryption is disabled"
        for finding in findings
    )


def test_remote_desktop_enabled():
    config = secure_config()
    config["remote_desktop_enabled"] = True

    policy = {
        "minimum_password_length": 12,
        "require_firewall": True,
        "require_antivirus": True,
        "require_automatic_updates": True,
        "require_mfa": False,
        "require_disk_encryption": False,
        "allow_remote_desktop": False,
        "allow_guest_account": False
    }

    findings = audit_configuration(config, policy)

    assert any(
        finding["issue"] == "Remote Desktop is enabled"
        for finding in findings
    )

