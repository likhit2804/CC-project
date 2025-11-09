# ==============================
#   Weighted Threat Severity Aggregator
# ==============================

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10
}

FEED_CONFIDENCE = {
    "otx": 0.9,
    "abuseipdb": 0.8,
    "shodan": 0.7,
    "greynoise": 0.6
}


def calculate_risk(correlated_findings):
    """
    Aggregates findings from multiple feeds into one unified severity.
    Uses confidence weighting to normalize feed influence.
    """
    if not correlated_findings:
        return "LOW"

    weighted_sum = 0
    total_weight = 0

    for f in correlated_findings:
        lvl = f.get("risk_level", f.get("risk", "LOW")).upper()
        feed = f.get("feed", "").lower()
        confidence = FEED_CONFIDENCE.get(feed, 0.5)

        weighted_sum += SEVERITY_WEIGHTS.get(lvl, 1) * confidence
        total_weight += confidence

    avg_score = weighted_sum / max(total_weight, 1)

    # Adaptive normalization thresholds
    if avg_score >= 8:
        return "CRITICAL"
    elif avg_score >= 5:
        return "HIGH"
    elif avg_score >= 2:
        return "MEDIUM"
    else:
        return "LOW"
