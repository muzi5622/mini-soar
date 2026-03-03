#!/usr/bin/env python3
import json, logging, time, os, subprocess, sys

class IOCBlocker:
    def __init__(self):
        self.load_config()
        self.setup_logging()
        
    def load_config(self):
        self.log_file = os.getenv('BLOCKER_LOG', 'logs/ioc_blocker.log')
        self.ioc_file = os.getenv('IOC_FILE', 'iocs.json')
        self.dns_cache_file = os.getenv('DNS_CACHE_FILE', 'dns_cache.json')
        self.allowlist_file = os.getenv('ALLOWLIST_FILE', 'allowlist.json')
        self.update_interval = int(os.getenv('BLOCKER_INTERVAL', '30'))
        self.nft_table = os.getenv('NFT_TABLE', 'iocblocker')
        self.nft_set = os.getenv('NFT_SET', 'block_v4')
        
    def setup_logging(self):
        self.logger = logging.getLogger('IOCBlocker')
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
        
    def load_iocs(self):
        try:
            if os.path.exists(self.ioc_file):
                with open(self.ioc_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('ips', []))
            return set()
        except:
            return set()
            
    def load_dns_cache(self):
        try:
            if os.path.exists(self.dns_cache_file):
                with open(self.dns_cache_file, 'r') as f:
                    return json.load(f)
            return {}
        except:
            return {}
            
    def load_allowlist(self):
        try:
            if os.path.exists(self.allowlist_file):
                with open(self.allowlist_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('ips', []))
            return set()
        except:
            return set()
            
    def block_ips(self, ips):
        try:
            allowlist = self.load_allowlist()
            ips_to_block = [ip for ip in ips if ip not in allowlist]
            
            if ips_to_block:
                ip_str = ', '.join(ips_to_block)
                cmd = f"nft add element inet {self.nft_table} {self.nft_set} {{ {ip_str} }}"
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                self.logger.info(f'Blocked {len(ips_to_block)} new IPs')
        except subprocess.CalledProcessError:
            self.logger.debug('IPs already in set or nftables update')
        except Exception as e:
            self.logger.error(f'Block failed: {str(e)}')
            
    def setup_nftables(self):
        try:
            subprocess.run(f"nft list table inet {self.nft_table}", shell=True, capture_output=True, check=True)
            self.logger.info('nftables table ready')
        except:
            self.logger.error('nftables not found')
            
    def run_daemon(self):
        self.logger.info(f'IOC Blocker daemon started (interval: {self.update_interval}s)')
        self.setup_nftables()
        try:
            while True:
                iocs = self.load_iocs()
                dns_cache = self.load_dns_cache()
                
                all_ips = set(iocs)
                for domain, ips in dns_cache.items():
                    all_ips.update(ips)
                    
                if all_ips:
                    self.block_ips(all_ips)
                    self.logger.info(f'Total IPs being blocked: {len(all_ips)}')
                    
                time.sleep(self.update_interval)
        except KeyboardInterrupt:
            self.logger.info('Blocker stopped')
            sys.exit(0)

if __name__ == '__main__':
    blocker = IOCBlocker()
    blocker.run_daemon()
