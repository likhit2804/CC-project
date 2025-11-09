RISK_ORDER = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
RISK_LEVEL_BY_WEIGHT = {v: k for k, v in RISK_ORDER.items()}

def escalate_risk(level, factor=1.0):
    """
    Escalates risk by a factor — allows multi-context influence.
    Example:
      factor=1.0 → +1 level
      factor=1.5 → +1.5 (rounded)
      factor=2.0 → +2 levels
    """
    current = RISK_ORDER.get(level.upper(), 1)
    new_weight = min(round(current + factor), 4)
    return RISK_LEVEL_BY_WEIGHT[new_weight]
