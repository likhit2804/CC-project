import requests, os, time
BASE = 'https://api.greynoise.io/v3/community'
class GreyNoiseAdapter:
    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key
        self.timeout = timeout
    def lookup_ip(self, ip):
        findings = []
        if not ip:
            return findings
        try:
            if not self.api_key:
                findings.append({'feed':'greynoise','ip':ip,'risk':'LOW','evidence':'no-api-key (dev)'})
                return findings
            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {'Accept':'application/json','Key': self.api_key}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('noise') is True:
                    findings.append({'feed':'greynoise','ip':ip,'risk':'MEDIUM','evidence':'noise=true'})
        except Exception:
            pass
        return findings
