SEVERITY_WEIGHTS = {
    'LOW': 1,
    'MEDIUM': 3,
    'HIGH': 6,
    'CRITICAL': 10
}

def calculate_risk(correlated_findings):
    """
    Weighted severity aggregator.
    Combines multiple feed results into one unified severity.
    """
    if not correlated_findings:
        return "LOW"

    total_score = 0
    for finding in correlated_findings:
        # Support both 'risk' and 'risk_level'
        lvl = finding.get('risk') or finding.get('risk_level', 'LOW')
        lvl = lvl.upper()
        total_score += SEVERITY_WEIGHTS.get(lvl, 0)

    # Apply threshold mapping
    if total_score >= 10:
        return "CRITICAL"
    elif total_score >= 6:
        return "HIGH"
    elif total_score >= 3:
        return "MEDIUM"
    else:
        return "LOW"
