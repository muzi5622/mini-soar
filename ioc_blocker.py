#!/usr/bin/env python3
"""
IOC Blocker - FIXED FOR ACTUAL BLOCKING
Blocks both INPUT and OUTPUT traffic (so ping/curl to blocked IPs fails)
"""

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

    def run_nft(self, *args):
        """Run nftables command using list of arguments (no shell)"""
        try:
            cmd = ['nft'] + list(args)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, '', str(e)

    def initialize_nftables(self):
        """Initialize nftables with INPUT and OUTPUT chains"""
        self.logger.info('Initializing nftables...')
        
        try:
            # 1. Flush
            self.logger.info('  [1/7] Flushing rules...')
            self.run_nft('flush', 'ruleset')
            time.sleep(1)
            
            # 2. Create table
            self.logger.info('  [2/7] Creating table...')
            self.run_nft('add', 'table', 'inet', self.nft_table)
            time.sleep(0.5)
            
            # 3. Create set
            self.logger.info('  [3/7] Creating set...')
            success, _, _ = self.run_nft('add', 'set', 'inet', self.nft_table, self.nft_set, 
                                         '{ type ipv4_addr; flags interval; }')
            if not success:
                self.logger.info('  Set already exists')
            time.sleep(0.5)
            
            # 4. Delete old chains
            self.logger.info('  [4/7] Cleaning old chains...')
            self.run_nft('delete', 'chain', 'inet', self.nft_table, 'input')
            self.run_nft('delete', 'chain', 'inet', self.nft_table, 'output')
            time.sleep(0.5)
            
            # 5. Create INPUT chain (blocks incoming from blocked IPs)
            self.logger.info('  [5/7] Creating INPUT chain (priority -100)...')
            success, stdout, stderr = self.run_nft('add', 'chain', 'inet', self.nft_table, 'input',
                                                   '{ type filter hook input priority -100; policy accept; }')
            if success:
                self.logger.info('  ✓ INPUT chain created')
            else:
                self.logger.error(f'  INPUT chain failed: {stderr}')
            time.sleep(0.5)
            
            # 6. Create OUTPUT chain (blocks outgoing to blocked IPs - THIS IS KEY FOR PING!)
            self.logger.info('  [6/7] Creating OUTPUT chain (priority -100)...')
            success, stdout, stderr = self.run_nft('add', 'chain', 'inet', self.nft_table, 'output',
                                                   '{ type filter hook output priority -100; policy accept; }')
            if success:
                self.logger.info('  ✓ OUTPUT chain created')
            else:
                self.logger.error(f'  OUTPUT chain failed: {stderr}')
            time.sleep(0.5)
            
            # 7. Add DROP rules to both chains
            self.logger.info('  [7/7] Adding DROP rules...')
            
            # INPUT: drop packets FROM blocked IPs
            success1, _, _ = self.run_nft('add', 'rule', 'inet', self.nft_table, 'input',
                                          'ip', 'saddr', '@' + self.nft_set, 'drop')
            
            # OUTPUT: drop packets TO blocked IPs (THIS IS KEY FOR PING!)
            success2, _, _ = self.run_nft('add', 'rule', 'inet', self.nft_table, 'output',
                                          'ip', 'daddr', '@' + self.nft_set, 'drop')
            
            if success1 and success2:
                self.logger.info('  ✓ Both DROP rules added')
                self.logger.info('✓ nftables initialized successfully (INPUT + OUTPUT blocking)')
                return True
            else:
                self.logger.error('  Failed to add DROP rules')
                return False
                
        except Exception as e:
            self.logger.error(f'Initialization failed: {str(e)}')
            return False

    def load_iocs(self):
        """Load direct IOC IPs"""
        try:
            if os.path.exists(self.ioc_file):
                with open(self.ioc_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('ips', []))
            return set()
        except:
            return set()

    def load_dns_cache(self):
        """Load resolved domains"""
        try:
            if os.path.exists(self.dns_cache_file):
                with open(self.dns_cache_file, 'r') as f:
                    return json.load(f)
            return {}
        except:
            return {}

    def load_allowlist(self):
        """Load allowlist"""
        try:
            if os.path.exists(self.allowlist_file):
                with open(self.allowlist_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('ips', []))
            return set()
        except:
            return set()

    def block_ips(self, ips):
        """Add IPs to nftables set"""
        if not ips:
            return 0
        
        try:
            allowlist = self.load_allowlist()
            ips_to_block = [ip for ip in ips if ip not in allowlist]
            
            if not ips_to_block:
                return 0
            
            # Batch add in groups of 50
            batch_size = 50
            total_added = 0
            
            for i in range(0, len(ips_to_block), batch_size):
                batch = ips_to_block[i:i + batch_size]
                
                # Build command: nft add element inet iocblocker block_v4 { 1.2.3.4, 5.6.7.8, ... }
                elements = ', '.join(batch)
                cmd = ['nft', 'add', 'element', 'inet', self.nft_table, self.nft_set, 
                       '{ ' + elements + ' }']
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    total_added += len(batch)
            
            if total_added > 0:
                self.logger.info(f'✓ Added {total_added} IPs to nftables')
            
            return total_added
            
        except Exception as e:
            self.logger.error(f'Failed to block IPs: {str(e)}')
            return 0

    def verify_drop_rules(self):
        """Verify DROP rules exist in both chains"""
        try:
            # Check INPUT
            success_in, stdout_in, _ = self.run_nft('list', 'chain', 'inet', self.nft_table, 'input')
            input_ok = success_in and 'drop' in stdout_in
            
            # Check OUTPUT
            success_out, stdout_out, _ = self.run_nft('list', 'chain', 'inet', self.nft_table, 'output')
            output_ok = success_out and 'drop' in stdout_out
            
            if input_ok and output_ok:
                return True
            else:
                self.logger.warning(f'DROP rules missing - INPUT: {input_ok}, OUTPUT: {output_ok}')
                return False
                
        except:
            return False

    def get_blocked_count(self):
        """Get count of blocked IPs"""
        try:
            success, stdout, _ = self.run_nft('list', 'set', 'inet', self.nft_table, self.nft_set)
            if success:
                return stdout.count('.')
            return 0
        except:
            return 0

    def run_daemon(self):
        """Main daemon loop"""
        self.logger.info('=' * 60)
        self.logger.info('IOC BLOCKER - Starting daemon (INPUT + OUTPUT blocking)')
        self.logger.info('=' * 60)
        
        # Initialize once
        if not self.initialize_nftables():
            self.logger.warning('nftables init had issues, but continuing...')
        
        time.sleep(2)
        
        cycle_count = 0
        
        try:
            while True:
                cycle_count += 1
                self.logger.info(f'[Cycle {cycle_count}] Processing IOCs')
                
                # Load all IPs
                direct_ips = self.load_iocs()
                dns_cache = self.load_dns_cache()
                
                # Combine
                all_ips = set(direct_ips)
                resolved_count = 0
                for domain, ips in dns_cache.items():
                    all_ips.update(ips)
                    resolved_count += len(ips)
                
                # Block them
                if all_ips:
                    self.logger.info(f'IPs: {len(direct_ips)} direct + {resolved_count} resolved = {len(all_ips)} total')
                    added = self.block_ips(list(all_ips))
                    
                    # Verify
                    blocked_count = self.get_blocked_count()
                    self.logger.info(f'Blocked in nftables: {blocked_count}')
                    
                    if not self.verify_drop_rules():
                        self.logger.warning('DROP rules missing!')
                else:
                    self.logger.warning('No IPs to block')
                
                # Wait
                time.sleep(self.update_interval)
                
        except KeyboardInterrupt:
            self.logger.info('Daemon stopped')
            sys.exit(0)
        except Exception as e:
            self.logger.error(f'Daemon error: {str(e)}')
            time.sleep(10)

if __name__ == '__main__':
    blocker = IOCBlocker()
    blocker.run_daemon()
