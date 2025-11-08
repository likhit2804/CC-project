import requests, os, time
SHODAN_BASE = 'https://api.shodan.io/shodan/host/'
class ShodanAdapter:
    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key
        self.timeout = timeout
    def lookup_host(self, host):
        findings = []
        if not host:
            return findings
        try:
            if not self.api_key:
                findings.append({'feed':'shodan','host':host,'risk':'LOW','evidence':'no-api-key (dev)'})
                return findings
            url = SHODAN_BASE + host
            params = {'key': self.api_key}
            resp = requests.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                # if port/service exposed with high risk tags, escalate
                vuln_score = 0
                if data.get('vulns'): vuln_score += len(data['vulns'])
                if data.get('data'):
                    for banner in data.get('data', []):
                        if 'apache' in str(banner.get('product','')).lower(): vuln_score += 1
                risk = 'LOW'
                if vuln_score > 0: risk = 'MEDIUM' if vuln_score < 5 else 'HIGH'
                findings.append({'feed':'shodan','host':host,'risk':risk,'evidence':f'vuln_count={vuln_score}'})
        except Exception:
            pass
        return findings
