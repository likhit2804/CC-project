def build_explanation(resource, correlated_findings, score):
    return {
        'resource_id': resource.get('resource_id'),
        'resource_type': resource.get('type'),
        'risk_score': score,
        'details': f"{len(correlated_findings)} correlated finding(s)",
        'findings': correlated_findings
    }
