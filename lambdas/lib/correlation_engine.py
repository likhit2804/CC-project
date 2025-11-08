def correlate_threats(resource, findings):
    attrs = resource.get('attributes', {})
    public = False
    if attrs.get('acl') in ('public-read', 'public-read-write') or attrs.get('public') is True:
        public = True
    if attrs.get('associate_public_ip_address') is True:
        public = True
    correlated = []
    for f in findings:
        lvl = f.get('risk','LOW')
        # escalate if public or feed says high
        if public or lvl in ('HIGH','CRITICAL'):
            correlated.append(f)
    return correlated
