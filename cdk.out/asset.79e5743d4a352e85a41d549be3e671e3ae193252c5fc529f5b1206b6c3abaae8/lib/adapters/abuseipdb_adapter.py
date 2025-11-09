import requests, os, time
BASE = 'https://api.abuseipdb.com/api/v2/check'
class AbuseIPDBAdapter:
    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key
        self.timeout = timeout
    def lookup_ip(self, ip):
        findings = []
        if not ip:
            return findings
        try:
            if not self.api_key:
                findings.append({'feed':'abuseipdb','ip':ip,'risk':'LOW','evidence':'no-api-key (dev)'})
                return findings
            headers = {'Key': self.api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            resp = requests.get(BASE, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                risk = 'LOW'
                if abuse_score >= 75: risk = 'HIGH'
                elif abuse_score >= 30: risk = 'MEDIUM'
                findings.append({'feed':'abuseipdb','ip':ip,'risk':risk,'evidence':f'abuse_score={abuse_score}'})
        except Exception:
            pass
        return findings
