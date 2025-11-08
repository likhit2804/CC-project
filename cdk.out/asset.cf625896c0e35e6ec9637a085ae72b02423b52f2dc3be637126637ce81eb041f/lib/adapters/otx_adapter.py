import requests, os, time
OTX_BASE = 'https://otx.alienvault.com/api/v1'

class OTXAdapter:
    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key
        self.timeout = timeout
    def search_for_resource(self, resource):
        # resource: dict with attributes. For production, inspect hostnames/ips and query OTX pulses/indicators.
        findings = []
        try:
            attrs = resource.get('attributes', {})
            candidates = []
            if attrs.get('endpoint'): candidates.append(attrs.get('endpoint'))
            # naive ip extraction from cidr or public_ip
            if attrs.get('public_ip'): candidates.append(attrs.get('public_ip'))
            for c in candidates:
                if not self.api_key: 
                    findings.append({'feed':'otx','indicator':c,'risk':'LOW','evidence':'no-api-key (dev)'}) 
                    continue
                url = f"{OTX_BASE}/indicators/IPv4/{c}/general"
                headers = {'X-OTX-API-KEY': self.api_key}
                resp = requests.get(url, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('reputation') and data['reputation'].get('malicious'):
                        findings.append({'feed':'otx','indicator':c,'risk':'HIGH','evidence':str(data.get('reputation'))})
        except Exception:
            pass
        return findings
