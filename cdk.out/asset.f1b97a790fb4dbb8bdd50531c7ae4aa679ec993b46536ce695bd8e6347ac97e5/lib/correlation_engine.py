# ==============================
#   Dynamic Context-Aware Correlation Engine
# ==============================

RISK_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

RISK_LEVEL_BY_WEIGHT = {v: k for k, v in RISK_ORDER.items()}


def escalate_risk(level, factor=1.0):
    """
    Escalates a risk level dynamically.
    factor = 1.0 → +1 level
    factor = 1.5 → +1.5 (rounded)
    """
    current = RISK_ORDER.get(level.upper(), 1)
    new_weight = min(round(current + factor), 4)
    return RISK_LEVEL_BY_WEIGHT[new_weight]


def correlate_threats(resource, findings):
    """
    Dynamically correlates findings using context like exposure, sensitivity, and ports.
    """
    attrs = resource.get("attributes", {})
    correlated_findings = []

    # --- Context detection ---
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

    # Check if resource exposes sensitive ports
    exposed_ports = []
    ports = attrs.get("port")
    if ports:
        if isinstance(ports, (int, str)):
            ports = [ports]
        for p in ports:
            try:
                if int(p) in [22, 80, 443, 3389, 3306]:
                    exposed_ports.append(int(p))
            except ValueError:
                continue

    # --- Determine context intensity ---
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

    # --- Apply escalation per finding ---
    for f in findings:
        correlated_f = f.copy()
        lvl = f.get("risk", f.get("risk_level", "LOW")).upper()

        if exposure_factor > 1.0:
            new_lvl = escalate_risk(lvl, factor=exposure_factor - 1)
            correlated_f["risk_level"] = new_lvl
            correlated_f["details"] = (
                f"Escalated {lvl}→{new_lvl} due to {', '.join(context_flags)} "
                f"(factor={exposure_factor:.2f}). Evidence: {f.get('evidence', 'N/A')}"
            )
        else:
            correlated_f["risk_level"] = lvl
            correlated_f["details"] = f"No escalation. Evidence: {f.get('evidence', 'N/A')}"

        correlated_f["context_flags"] = context_flags
        correlated_findings.append(correlated_f)

    return correlated_findings
