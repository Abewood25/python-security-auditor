
SEVERITY_WEIGHTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1
}


def calculate_risk_score(findings):
    score = 0

    for finding in findings:
        severity = finding["severity"]
        score += SEVERITY_WEIGHTS.get(severity, 0)

    return score


def summarize_findings(findings):
    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = finding["severity"]

        if severity in summary:
            summary[severity] += 1

    return summary


def determine_risk_level(score):
    if score >= 30:
        return "CRITICAL"
    elif score >= 20:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    else:
        return "LOW"
