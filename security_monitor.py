#!/usr/bin/env python3

import os
import requests
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

@dataclass
class SecurityResult:
    """Class to hold security check results."""
    value: str
    type: str  # 'ip' or 'url'
    threat_score: float
    last_seen: datetime
    details: Dict[str, Any]

class SecurityAPIMonitor:
    """Handle security API lookups for IPs and URLs."""

    def __init__(self):
        # Get API keys from environment variables
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.vt_key = os.getenv('VT_API_KEY')
        
        # Validate API keys exist
        if not self.abuseipdb_key:
            raise ValueError("ABUSEIPDB_API_KEY environment variable not set")
        if not self.vt_key:
            raise ValueError("VT_API_KEY environment variable not set")
            
        # Rate limiting setup
        self.last_query_time = {'abuseipdb': 0, 'virustotal': 0}
        self.min_query_interval = {'abuseipdb': 1, 'virustotal': 15}

    def _rate_limit(self, api: str) -> None:
        """Implement rate limiting for API calls."""
        current_time = time.time()
        elapsed = current_time - self.last_query_time[api]
        if elapsed < self.min_query_interval[api]:
            time.sleep(self.min_query_interval[api] - elapsed)
        self.last_query_time[api] = time.time()

    def check_abuseipdb(self, ip: str) -> Dict:
        """Check IP against AbuseIPDB."""
        self._rate_limit('abuseipdb')
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': True
            }
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"AbuseIPDB error for {ip}: {response.status_code}")
                return {}
                
        except Exception as e:
            print(f"AbuseIPDB request failed for {ip}: {str(e)}")
            return {}

    def check_virustotal(self, ip: str) -> Dict:
        """Check IP against VirusTotal."""
        self._rate_limit('virustotal')
        
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {
                'x-apikey': self.vt_key
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json().get('data', {}).get('attributes', {})
            else:
                print(f"VirusTotal error for {ip}: {response.status_code}")
                return {}
                
        except Exception as e:
            print(f"VirusTotal request failed for {ip}: {str(e)}")
            return {}

    def calculate_threat_score(self, abuse_data: Dict, vt_data: Dict) -> float:
        """Calculate overall threat score from multiple sources."""
        score = 0.0
        count = 0
        
        # AbuseIPDB score (weighted 60%)
        if abuse_data and 'data' in abuse_data:
            abuse_score = abuse_data['data'].get('abuseConfidenceScore')
            if abuse_score is not None:
                score += abuse_score * 0.6
                count += 1
        
        # VirusTotal score (weighted 40%)
        if vt_data:
            stats = vt_data.get('last_analysis_stats', {})
            if stats:
                total = sum(stats.values())
                if total > 0:
                    malicious = stats.get('malicious', 0)
                    vt_score = (malicious / total) * 100
                    score += vt_score * 0.4
                    count += 1
        
        # Return weighted average or 0 if no data
        return round(score / count, 1) if count > 0 else 0.0

    def get_last_seen(self, abuse_data: Dict, vt_data: Dict) -> Optional[datetime]:
        """Get the most recent date from available data."""
        dates = []
        
        # Check AbuseIPDB last reported date
        if abuse_data and 'data' in abuse_data:
            last_reported = abuse_data['data'].get('lastReportedAt')
            if last_reported:
                try:
                    dates.append(datetime.fromisoformat(last_reported.replace('Z', '+00:00')))
                except (ValueError, AttributeError):
                    pass
        
        # Check VirusTotal last analysis date
        if vt_data:
            last_analysis = vt_data.get('last_analysis_date')
            if last_analysis:
                try:
                    dates.append(datetime.fromtimestamp(last_analysis))
                except (ValueError, TypeError):
                    pass
        
        return max(dates) if dates else None

    def query_batch(self, indicators: List[str]) -> List[SecurityResult]:
        """Process a batch of indicators (IPs or URLs)."""
        results = []
        
        for indicator in indicators:
            # For now, we only handle IPs
            indicator_type = 'ip'
            
            # Get data from both sources
            abuse_data = self.check_abuseipdb(indicator)
            vt_data = self.check_virustotal(indicator)
            
            # Calculate threat score
            threat_score = self.calculate_threat_score(abuse_data, vt_data)
            
            # Get last seen date
            last_seen = self.get_last_seen(abuse_data, vt_data)
            
            # Create result object
            result = SecurityResult(
                value=indicator,
                type=indicator_type,
                threat_score=threat_score,
                last_seen=last_seen or datetime.now(),
                details={
                    'abuseipdb': abuse_data,
                    'virustotal': vt_data
                }
            )
            
            results.append(result)
            
        return results

if __name__ == "__main__":
    # Example usage
    import sys
    
    # Check environment variables
    if not os.getenv('ABUSEIPDB_API_KEY') or not os.getenv('VT_API_KEY'):
        print("Please set ABUSEIPDB_API_KEY and VT_API_KEY environment variables")
        print("Example:")
        print("  export ABUSEIPDB_API_KEY=your_key_here")
        print("  export VT_API_KEY=your_key_here")
        sys.exit(1)
    
    try:
        # Initialize monitor
        monitor = SecurityAPIMonitor()
        
        # Check some IPs
        test_ips = ['8.8.8.8', '1.1.1.1']
        results = monitor.query_batch(test_ips)
        
        # Print results
        for result in results:
            print(f"\nResults for {result.value}:")
            print(f"Threat Score: {result.threat_score}")
            print(f"Last Seen: {result.last_seen}")
            print("AbuseIPDB Score:", 
                  result.details['abuseipdb'].get('data', {}).get('abuseConfidenceScore', 'N/A'))
            vt_stats = result.details['virustotal'].get('last_analysis_stats', {})
            print("VirusTotal Detections:", 
                  f"{vt_stats.get('malicious', 0)}/{sum(vt_stats.values()) if vt_stats else 0}")
            
    except ValueError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)