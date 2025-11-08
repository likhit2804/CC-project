# Aggregates multiple adapters and normalizes results
from .otx_adapter import OTXAdapter
from .shodan_adapter import ShodanAdapter
from .abuseipdb_adapter import AbuseIPDBAdapter
from .greynoise_adapter import GreyNoiseAdapter
import os

class ThreatAggregator:
    def __init__(self, cache_table=None):
        self.cache_table = cache_table
        self.otx = OTXAdapter(os.environ.get('OTX_API_KEY'))
        self.shodan = ShodanAdapter(os.environ.get('SHODAN_API_KEY'))
        self.abuse = AbuseIPDBAdapter(os.environ.get('ABUSEIPDB_API_KEY'))
        self.greynoise = GreyNoiseAdapter(os.environ.get('GREYNOISE_API_KEY'))

    def check_resource(self, resource):
        attrs = resource.get('attributes', {})
        findings = []
        # extract candidate IPs/hosts/ports from common attributes
        ips = []
        if 'associate_public_ip_address' in attrs and attrs.get('associate_public_ip_address') is True:
            if attrs.get('public_ip'): ips.append(attrs.get('public_ip'))
        if 'cidr_block' in attrs:
            ips.append(attrs.get('cidr_block'))
        if 'endpoint' in attrs:
            ips.append(attrs.get('endpoint'))
        # dedupe
        ips = [i for i in set(ips) if i]
        for ip in ips:
            # query adapters - adapters should handle normalization/caching
            try:
                findings += self.abuse.lookup_ip(ip)
                findings += self.greynoise.lookup_ip(ip)
                findings += self.shodan.lookup_host(ip)
            except Exception:
                # adapters should use safe timeouts; we continue gracefully
                continue
        # OTX may return indicators by domain or IP from resource metadata
        try:
            findings += self.otx.search_for_resource(resource)
        except Exception:
            pass
        return findings
