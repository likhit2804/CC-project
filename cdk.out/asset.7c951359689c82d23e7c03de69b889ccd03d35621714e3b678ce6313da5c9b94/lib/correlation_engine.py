import math

# ==============================
# 🔹 Base Risk Mappings
# ==============================
RISK_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

RISK_LEVEL_BY_WEIGHT = {v: k for k, v in RISK_ORDER.items()}

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10
}

# Feed reliability confidence — tweakable
FEED_CONFIDENCE = {
    "otx": 0.9,
    "abuseipdb": 0.8,
    "shodan": 0.7,
    "greynoise": 0.6
}


# ==============================
# 🔹 Risk Escalation Utility
# ==============================
def escalate_risk(level, factor=1.0):
    """
    Escalates a risk level dynamically based on context factor.
    factor = 1.0 → +1 level
    factor = 1.5 → +1.5 (rounded)
    factor = 2.0 → +2 levels
    """
    current = RISK_ORDER.get(level.upper(), 1)
    new_weight = min(round(current + factor), 4)
    return RISK_LEVEL_BY_WEIGHT[new_weight]


# ==============================
# 🔹 Context-Aware Correlation
# ==============================
def correlate_threats(resource, findings):
    """
    Dynamically correlates threat intelligence findings using
    resource context such as exposure, sensitivity, and ACLs.
    """
    attrs = resource.get("attributes", {})
    correlated_findings = []

    # === Context Flags ===
    public = any([
        attrs.get("public") is True,
        attrs.get("associate_public_ip_address") is True,
        attrs.get("acl") in ("public-read", "public-read-write"),
        "0.0.0.0/0" in str(attrs)
    ])

    sensitive = any([
        "prod" in str(attrs.get("tags", [])).lower(),
        "critical" in str(attrs.get("tags", [])).lower(),
        "db" in str(attrs.get("name", "")).lower(),
        "backup" in str(attrs.get("name", "")).lower()
    ])

    exposed_ports = []
    if "port" in attrs:
        ports = attrs.get("port")
        if isinstance(ports, (int, str)):
            ports = [ports]
        for p in ports:
            if int(p) in [22, 3389, 80, 443, 3306]:
                exposed_ports.append(int(p))

    # === Escalation Factor ===
    exposure_factor = 1.0
    if public:
        exposure_factor += 0.7
    if sensitive:
        exposure_factor += 0.4
    if exposed_ports:
        exposure_factor += 0.3

    context_flags = []
    if public:
        context_flags.append("public")
    if sensitive:
        context_flags.append("sensitive")
    if exposed_ports:
        context_flags.append("exposed_ports")

    # === Process Findings ===
    for f in findings:
        correlated = f.copy()
        lvl = f.get("risk_level") or f.get("risk", "LOW")
        lvl = lvl.upper()

        # Apply context escalation
        if exposure_factor > 1.0:
            new_lvl = escalate_risk(lvl, factor=exposure_factor - 1)
            correlated["risk_level"] = new_lvl
            correlated["details"] = (
                f"Escalated {lvl}→{new_lvl} due to {', '.join(context_flags)} context "
                f"(factor={exposure_factor:.2f}). Evidence: {f.get('evidence', 'N/A')}"
            )
        else:
            correlated["risk_level"] = lvl

        correlated["context_flags"] = context_flags
        correlated_findings.append(correlated)

    return correlated_findings


# ==============================
# 🔹 Weighted Severity Aggregator
# ==============================
def calculate_risk(correlated_findings):
    """
    Aggregates risk across multiple feeds, using confidence weighting.
    Produces a single normalized risk severity (LOW → CRITICAL).
    """
    if not correlated_findings:
        return "LOW"

    weighted_sum = 0
    total_weight = 0

    for f in correlated_findings:
        lvl = f.get("risk_level") or f.get("risk", "LOW")
        lvl = lvl.upper()
        feed = f.get("feed", "").lower()

        confidence = FEED_CONFIDENCE.get(feed, 0.5)
        weighted_sum += SEVERITY_WEIGHTS.get(lvl, 1) * confidence
        total_weight += confidence

    # Normalize average score
    avg_score = weighted_sum / max(total_weight, 1)

    # Adaptive thresholds — scales to weighted intensity
    if avg_score >= 8:
        return "CRITICAL"
    elif avg_score >= 5:
        return "HIGH"
    elif avg_score >= 2:
        return "MEDIUM"
    else:
        return "LOW"


# ==============================
# 🔹 Unified Risk Evaluation
# ==============================
def evaluate_resource_risk(resource, findings):
    """
    One-call helper: correlates threats, computes final risk,
    and returns an explainable output.
    """
    correlated = correlate_threats(resource, findings)
    final_risk = calculate_risk(correlated)

    # Compute mean risk score for transparency
    severity_scores = {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 6,
        "CRITICAL": 10
    }

    avg_score = sum(severity_scores[f["risk_level"]] for f in correlated) / len(correlated)

    return {
        "resource_name": resource.get("attributes", {}).get("name", "unknown"),
        "final_risk": final_risk,
        "average_score": round(avg_score, 2),
        "context_summary": correlated[0].get("context_flags", []),
        "findings": correlated
    }

