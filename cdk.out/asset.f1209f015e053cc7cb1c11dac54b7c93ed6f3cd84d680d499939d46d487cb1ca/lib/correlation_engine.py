# A mapping of risk levels to a numeric weight for escalation.
RISK_ORDER = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4
}
# A reverse mapping to convert numeric weight back to a string.
RISK_LEVEL_BY_WEIGHT = {
    1: 'LOW',
    2: 'MEDIUM',
    3: 'HIGH',
    4: 'CRITICAL'
}

def escalate_risk(level):
    """
    Escalates a risk level by one, capping at CRITICAL.
    """
    # Convert string level to a numeric weight
    current_weight = RISK_ORDER.get(level.upper(), 1)
    
    # Escalate by one level
    new_weight = min(current_weight + 1, 4) # Cap at 4 (CRITICAL)
    
    # Convert back to string
    return RISK_LEVEL_BY_WEIGHT[new_weight]

def correlate_threats(resource, findings):
    """
    Correlates findings with resource context.
    
    Instead of filtering, this function escalates the risk of findings
    if the resource is determined to be public-facing.
    """
    attrs = resource.get('attributes', {})
    public = False
    
    # Check for various common "public" attributes
    if attrs.get('acl') in ('public-read', 'public-read-write') or attrs.get('public') is True:
        public = True
    if attrs.get('associate_public_ip_address') is True:
        public = True
    
    # Check for public CIDR blocks in security groups or network rules
    # This is a simple check; a real implementation would parse CIDR ranges.
    if '0.0.0.0/0' in str(attrs):
        public = True
        
    correlated_findings = []
    
    for f in findings:
        # Create a copy to avoid modifying the original finding dictionary
        correlated_f = f.copy()
        
        # Get the risk level, defaulting to 'LOW'
        lvl = correlated_f.get('risk', correlated_f.get('risk_level', 'LOW')).upper()
        
        if public:
            # If the resource is public, escalate the finding's risk
            new_lvl = escalate_risk(lvl)
            correlated_f['risk_level'] = new_lvl
            
            # Add a note about why it was escalated
            correlated_f['details'] = f"Risk escalated from {lvl} to {new_lvl} due to public exposure. Original evidence: {correlated_f.get('evidence', 'N/A')}"
        else:
            # If not public, just ensure the risk_level key is set
            correlated_f['risk_level'] = lvl

        correlated_findings.append(correlated_f)
        
    return correlated_findings