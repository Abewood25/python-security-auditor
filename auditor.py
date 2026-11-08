
def audit_configuration(config):
    findings = []

    if not config.get("firewall_enabled", False):
        findings.append({
            "severity": "HIGH",
            "issue": "Firewall is disabled",
            "recommendation": "Enable the host firewall."
        })

    if not config.get("antivirus_enabled", False):
        findings.append({
            "severity": "HIGH",
            "issue": "Antivirus protection is disabled",
            "recommendation": "Enable endpoint protection."
        })

    if not config.get("automatic_updates", False):
        findings.append({
            "severity": "MEDIUM",
            "issue": "Automatic updates are disabled",
            "recommendation": "Establish a controlled patching process."
        })

    if config.get("guest_account_enabled", False):
        findings.append({
            "severity": "MEDIUM",
            "issue": "Guest account is enabled",
            "recommendation": "Disable unused guest accounts."
        })

    if config.get("minimum_password_length", 0) < 12:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Minimum password length is below 12",
            "recommendation": "Review and strengthen the password policy."
        })

    for service in config.get("unnecessary_services", []):
        findings.append({
            "severity": "MEDIUM",
            "issue": f"Unnecessary service: {service}",
            "recommendation": "Disable the service if not required."
        })

    return findings
