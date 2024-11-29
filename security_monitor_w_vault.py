import requests, json, time, logging, hashlib, os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from vault_util import get_secrets

@dataclass
class APIConfig:
    virustotal_api_key: str
    abuseipdb_api_key: str
    urlscan_api_key: str
    base_path: str = "security_data"

@dataclass
class ThreatIndicator:
    type: str  # 'ip' or 'url'
    value: str
    source: str
    threat_score: float
    last_seen: datetime
    details: Dict
    
class SecurityAPIMonitor:
    def __init__(self):
        """Initialize with Vault client instead of direct API keys"""
        
        # Get API keys from Vault
        api_keys = get_secrets(
            secret_path="infosec_secrets",
            vault_url='https://vault.qube.en.internal.quadrature',
            mount_point="systems-security-kv/"
        )
        
        self.config = APIConfig(
            virustotal_api_key=api_keys['virus_total_api'],
            abuseipdb_api_key=api_keys['abuseIPDB_api'],
            urlscan_api_key=api_keys['url_scan_io_api']
        )
        
        self.logger = self._setup_logging()
        self._setup_storage()
        
        self.cache_file = os.path.join(self.config.base_path, 'cache.json')
        self.cache = self._load_cache()
        
        self.endpoints = {
            'virustotal': 'https://www.virustotal.com/vtapi/v2',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2',
            'urlscan': 'https://urlscan.io/api/v1'
        }

    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger('SecurityAPIMonitor')
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        fh = logging.FileHandler('security_api_monitor.log')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        return logger

    def _setup_storage(self):
        """Setup storage directories"""
        os.makedirs(self.config.base_path, exist_ok=True)
        os.makedirs(os.path.join(self.config.base_path, 'reports'), exist_ok=True)
        os.makedirs(os.path.join(self.config.base_path, 'indicators'), exist_ok=True)

    def _load_cache(self) -> Dict:
        """Load cached results"""
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        """Save results to cache"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f)

    def query_indicator(self, value: str) -> ThreatIndicator:
        """Query a single IP address or URL"""
        # Determine if input is IP or URL
        import re
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        
        indicator_type = 'ip' if ip_pattern.match(value) else 'url'
        return self.check_indicator(value, indicator_type)

    def query_batch(self, values: List[str]) -> List[ThreatIndicator]:
        """Query multiple IPs or URLs"""
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(self.query_indicator, value)
                for value in values
            ]
            return [f.result() for f in futures]

    def check_virustotal(self, indicator: str, type: str) -> Dict:
        """Query VirusTotal API"""
        endpoint = f"{self.endpoints['virustotal']}"
        
        if type == 'ip':
            endpoint += '/ip-address/report'
            params = {'ip': indicator}
        else:  # URL
            endpoint += '/url/report'
            params = {'resource': indicator}
            
        params['apikey'] = self.config.virustotal_api_key
        
        try:
            response = requests.get(endpoint, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal API error: {str(e)}")
            return {}

    def check_abuseipdb(self, ip: str) -> Dict:
        """Query AbuseIPDB API"""
        endpoint = f"{self.endpoints['abuseipdb']}/check"
        headers = {
            'Key': self.config.abuseipdb_api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            response = requests.get(endpoint, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"AbuseIPDB API error: {str(e)}")
            return {}

    def check_urlscan(self, url: str) -> Dict:
        """Query URLScan.io API"""
        endpoint = f"{self.endpoints['urlscan']}/scan/"
        headers = {
            'API-Key': self.config.urlscan_api_key,
            'Content-Type': 'application/json'
        }
        data = {
            'url': url,
            'visibility': 'public'
        }
        
        try:
            response = requests.post(endpoint, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"URLScan API error: {str(e)}")
            return {}

    def calculate_threat_score(self, results: Dict, indicator_type: str) -> float:
        """Calculate normalized threat score from API results"""
        score = 0.0
        
        if indicator_type == 'ip':
            # AbuseIPDB score (40% weight)
            if 'data' in results.get('abuseipdb', {}):
                score += results['abuseipdb']['data']['abuseConfidenceScore'] / 100 * 0.4
            
            # VirusTotal score (60% weight)
            if 'detected_urls' in results.get('virustotal', {}):
                vt_score = len(results['virustotal']['detected_urls']) / 100
                score += min(vt_score, 1.0) * 0.6
                
        else:  # URL
            # VirusTotal score (70% weight)
            if 'positives' in results.get('virustotal', {}):
                score += results['virustotal']['positives'] / 100 * 0.7
            
            # URLScan score (30% weight)
            if 'verdicts' in results.get('urlscan', {}):
                if results['urlscan']['verdicts'].get('malicious', False):
                    score += 0.3
                    
        return min(score, 1.0)

    def check_indicator(self, indicator: str, indicator_type: str) -> ThreatIndicator:
        """Check a single indicator across all relevant APIs"""
        results = {}
        
        # Check cache first
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if datetime.now() - datetime.fromisoformat(cache_entry['timestamp']) < timedelta(hours=6):
                self.logger.info(f"Cache hit for {indicator}")
                return ThreatIndicator(**cache_entry['data'])
        
        self.logger.info(f"Checking {indicator_type}: {indicator}")
        
        # Gather results from relevant APIs
        results['virustotal'] = self.check_virustotal(indicator, indicator_type)
        
        if indicator_type == 'ip':
            results['abuseipdb'] = self.check_abuseipdb(indicator)
        else:  # URL
            results['urlscan'] = self.check_urlscan(indicator)
            
        # Calculate threat score
        threat_score = self.calculate_threat_score(results, indicator_type)
        
        # Create threat indicator
        threat_indicator = ThreatIndicator(
            type=indicator_type,
            value=indicator,
            source='multi',
            threat_score=threat_score,
            last_seen=datetime.now(),
            details=results
        )
        
        # Update cache
        self.cache[cache_key] = {
            'timestamp': datetime.now().isoformat(),
            'data': {
                'type': threat_indicator.type,
                'value': threat_indicator.value,
                'source': threat_indicator.source,
                'threat_score': threat_indicator.threat_score,
                'last_seen': threat_indicator.last_seen.isoformat(),
                'details': threat_indicator.details
            }
        }
        self._save_cache()
        
        return threat_indicator

    def generate_report(self, indicators: List[ThreatIndicator], min_threat_score: float = 0.7) -> str:
        """Generate a detailed report of findings"""
        report = [
            "Security Indicator Report",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Indicators Checked: {len(indicators)}",
            f"\nHigh Risk Indicators (Threat Score > {min_threat_score}):",
            "-" * 50
        ]
        
        # Sort by threat score
        sorted_indicators = sorted(
            indicators,
            key=lambda x: x.threat_score,
            reverse=True
        )
        
        for indicator in sorted_indicators:
            if indicator.threat_score > min_threat_score:
                report.append(
                    f"\nType: {indicator.type}"
                    f"\nValue: {indicator.value}"
                    f"\nThreat Score: {indicator.threat_score:.2f}"
                    f"\nLast Seen: {indicator.last_seen}"
                )
                
                # Add API-specific details
                if indicator.type == 'ip' and 'abuseipdb' in indicator.details:
                    report.append(f"AbuseIPDB Confidence: {indicator.details['abuseipdb'].get('data', {}).get('abuseConfidenceScore', 'N/A')}%")
                
                if 'virustotal' in indicator.details:
                    vt_positives = indicator.details['virustotal'].get('positives', 'N/A')
                    report.append(f"VirusTotal Positives: {vt_positives}")
                
                report.append(f"\n{'-' * 30}")
        
        report_path = os.path.join(
            self.config.base_path,
            'reports',
            f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        )
        
        with open(report_path, 'w') as f:
            f.write('\n'.join(report))
            
        return '\n'.join(report)

def main():
    # Example usage
    monitor = SecurityAPIMonitor()
    
    # Example batch of mixed IPs and URLs to check
    indicators_to_check = [
        "1.2.3.4",
        "8.8.8.8",
        "http://example.com",
        "https://google.com",
        "192.168.1.1"
    ]
    
    # Query all indicators
    results = monitor.query_batch(indicators_to_check)
    
    # Generate and print report
    report = monitor.generate_report(results)
    print(report)

if __name__ == "__main__":
    main()