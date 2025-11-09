def parse_iac_plan(plan_json):
    parsed = []
    for rc in plan_json.get('resource_changes', []):
        rtype = rc.get('type') or rc.get('address')
        name = rc.get('name') or rc.get('address')
        change = rc.get('change') or {}
        after = change.get('after') or rc.get('after') or {}
        parsed.append({
            'resource_id': rc.get('address') or f"{rtype}.{name}",
            'type': rtype,
            'name': name,
            'attributes': after
        })
    # fallback scan for simple maps
    if not parsed:
        for k,v in plan_json.items():
            if isinstance(v, dict) and (k.startswith('aws_') or k.startswith('azurerm_')):
                parsed.append({'resource_id':k,'type':k,'name':k,'attributes':v})
    return parsed
