

def audit_configuration(config, policy=None):
    if policy is None:
        policy = {
            "minimum_password_length": 12,
            "require_firewall": True,
            "require_antivirus": True,
            "require_automatic_updates": True,
            "require_mfa": False,
            "require_disk_encryption": False,
            "allow_remote_desktop": True,
            "allow_guest_account": False
        }

    findings = []

    def add_finding(severity, issue, recommendation):
        findings.append({
            "severity": severity,
            "issue": issue,
            "recommendation": recommendation
        })

    if policy["require_firewall"] and not config.get("firewall_enabled", False):
        add_finding(
            "HIGH",
            "Firewall is disabled",
            "Enable the host firewall."
        )

    if policy["require_antivirus"] and not config.get("antivirus_enabled", False):
        add_finding(
            "HIGH",
            "Antivirus protection is disabled",
            "Enable endpoint protection."
        )

    if policy["require_automatic_updates"] and not config.get("automatic_updates", False):
        add_finding(
            "MEDIUM",
            "Automatic updates are disabled",
            "Establish a controlled patching process."
        )

    if not policy["allow_guest_account"] and config.get("guest_account_enabled", False):
        add_finding(
            "MEDIUM",
            "Guest account is enabled",
            "Disable unused guest accounts."
        )

    minimum_length = policy["minimum_password_length"]

    if config.get("minimum_password_length", 0) < minimum_length:
        add_finding(
            "MEDIUM",
            f"Minimum password length is below {minimum_length}",
            "Review and strengthen the password policy."
        )

    if policy["require_mfa"] and not config.get("mfa_enabled", False):
        add_finding(
            "HIGH",
            "Multi-factor authentication is disabled",
            "Require MFA for applicable user accounts."
        )

    if policy["require_disk_encryption"] and not config.get("disk_encryption_enabled", False):
        add_finding(
            "HIGH",
            "Disk encryption is disabled",
            "Enable approved full-disk encryption."
        )

    if not policy["allow_remote_desktop"] and config.get("remote_desktop_enabled", False):
        add_finding(
            "MEDIUM",
            "Remote Desktop is enabled",
            "Disable Remote Desktop unless explicitly authorized."
        )

    for service in config.get("unnecessary_services", []):
        add_finding(
            "MEDIUM",
            f"Unnecessary service: {service}",
            "Disable the service if not required."
        )

    return findings

