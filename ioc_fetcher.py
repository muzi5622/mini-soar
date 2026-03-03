#!/usr/bin/env python3
import requests, json, logging, time, os, sys, socket
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class IOCFetcher:
    def __init__(self):
        self.load_config()
        self.setup_logging()
        self.iocs = {'domains': set(), 'ips': set()}
        self.session = requests.Session()
        self.session.headers.update({'X-API-Key': self.api_key})
        
    def load_config(self):
        self.api_key = os.getenv('API_KEY', 'BANK123')
        self.fetch_url = os.getenv('IOC_ENDPOINT', 'http://40.81.244.175:9000/share/partners/bank/iocs_high.json')
        self.fetch_interval = int(os.getenv('FETCH_INTERVAL', '3600'))
        self.log_file = os.getenv('FETCHER_LOG', 'logs/ioc_fetcher.log')
        self.ioc_file = os.getenv('IOC_FILE', 'iocs.json')
        self.dns_cache_file = os.getenv('DNS_CACHE_FILE', 'dns_cache.json')
        
    def setup_logging(self):
        self.logger = logging.getLogger('IOCFetcher')
        self.logger.setLevel(logging.INFO)
        os.makedirs(os.path.dirname(self.log_file) or '.', exist_ok=True)
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)-10s %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
    def fetch_iocs(self):
        try:
            self.logger.info(f'Fetching IOCs from endpoint...')
            response = self.session.get(self.fetch_url, timeout=30, verify=False)
            response.raise_for_status()
            bundle = response.json()
            self.parse_bundle(bundle)
            self.save_iocs()
            self.resolve_domains()
            return True
        except Exception as e:
            self.logger.error(f'Fetch failed: {str(e)}')
            return False
            
    def parse_bundle(self, bundle):
        if not isinstance(bundle, dict) or bundle.get('type') != 'bundle':
            return
        objects = bundle.get('objects', [])
        domain_count = 0
        ip_count = 0
        for obj in objects:
            if obj.get('type') == 'indicator':
                pattern = obj.get('pattern', '')
                if 'domain-name:value' in pattern:
                    try:
                        domain = pattern.split("'")[1]
                        self.iocs['domains'].add(domain)
                        domain_count += 1
                    except: pass
                elif 'ipv4-addr:value' in pattern:
                    try:
                        ip = pattern.split("'")[1]
                        self.iocs['ips'].add(ip)
                        ip_count += 1
                    except: pass
        self.logger.info(f'Parsed: {domain_count} domains + {ip_count} IPs')
        
    def save_iocs(self):
        try:
            data = {
                'timestamp': datetime.utcnow().isoformat(),
                'domains': sorted(list(self.iocs['domains'])),
                'ips': sorted(list(self.iocs['ips']))
            }
            with open(self.ioc_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f'Saved: {len(self.iocs["domains"])} domains, {len(self.iocs["ips"])} IPs')
        except Exception as e:
            self.logger.error(f'Save failed: {str(e)}')
            
    def resolve_domains(self):
        dns_cache = {}
        self.logger.info('Resolving domains to IPs...')
        for domain in self.iocs['domains']:
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                dns_cache[domain] = ips
                self.logger.info(f'  {domain} -> {", ".join(ips)}')
            except socket.gaierror:
                self.logger.warning(f'  Cannot resolve: {domain}')
                dns_cache[domain] = []
            except Exception as e:
                dns_cache[domain] = []
        try:
            with open(self.dns_cache_file, 'w') as f:
                json.dump(dns_cache, f, indent=2)
        except: pass
        return dns_cache
        
    def run_daemon(self):
        self.logger.info(f'IOC Fetcher daemon started (interval: {self.fetch_interval}s)')
        try:
            while True:
                self.fetch_iocs()
                time.sleep(self.fetch_interval)
        except KeyboardInterrupt:
            self.logger.info('Fetcher stopped')
            sys.exit(0)

if __name__ == '__main__':
    fetcher = IOCFetcher()
    fetcher.run_daemon()
