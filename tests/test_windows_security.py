
from windows_security import audit_firewall_profiles


def test_all_firewalls_enabled():
    profiles = [
        {"Name": "Domain", "Enabled": True},
        {"Name": "Private", "Enabled": True},
        {"Name": "Public", "Enabled": True}
    ]

    findings = audit_firewall_profiles(profiles)

    assert len(findings) == 0


def test_public_firewall_disabled():
    profiles = [
        {"Name": "Domain", "Enabled": True},
        {"Name": "Private", "Enabled": True},
        {"Name": "Public", "Enabled": False}
    ]

    findings = audit_firewall_profiles(profiles)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "Public" in findings[0]["issue"]


def test_multiple_firewalls_disabled():
    profiles = [
        {"Name": "Domain", "Enabled": False},
        {"Name": "Private", "Enabled": False},
        {"Name": "Public", "Enabled": True}
    ]

    findings = audit_firewall_profiles(profiles)

    assert len(findings) == 2
