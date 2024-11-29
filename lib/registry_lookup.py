#!/usr/bin/env python3

import requests
import ipaddress
from ipwhois import IPWhois
import time
import random

class RegistryLookup:
    """Handle lookups across different regional internet registries."""
    
    REGISTRY_ENDPOINTS = {
        'RIPE': 'https://rest.db.ripe.net/search.json',
        'ARIN': 'https://whois.arin.net/rest/ip/',
        'APNIC': 'https://wq.apnic.net/query',
        'AFRINIC': 'https://rdap.afrinic.net/rdap/ip/',
        'LACNIC': 'https://rdap.lacnic.net/rdap/ip/'
    }

    def __init__(self):
        self.last_query_time = {}
        self.min_query_interval = 1.0

    def determine_registry(self, ip):
        """
        Determine which registry an IP belongs to.
        Returns registry name or None if unable to determine.
        """
        try:
            # Try IPWhois first as it's more reliable
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            if results and 'asn_registry' in results:
                return results['asn_registry'].upper()
        except Exception as e:
            print(f"IPWhois lookup failed for {ip}: {str(e)}")

        try:
            # Fallback to RDAP bootstrap
            response = requests.get(
                f"https://rdap-bootstrap.arin.net/bootstrap/ip/{ip}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if 'services' in data and len(data['services']) > 0:
                    if len(data['services'][0]) > 0:
                        service_url = data['services'][0][0]
                        if 'ripe.net' in service_url:
                            return 'RIPE'
                        elif 'arin.net' in service_url:
                            return 'ARIN'
                        elif 'apnic.net' in service_url:
                            return 'APNIC'
                        elif 'afrinic.net' in service_url:
                            return 'AFRINIC'
                        elif 'lacnic.net' in service_url:
                            return 'LACNIC'
        except Exception as e:
            print(f"RDAP bootstrap error for {ip}: {str(e)}")

        return None

    def _rate_limit(self, registry):
        """Implement rate limiting for registry queries."""
        if registry in self.last_query_time:
            elapsed = time.time() - self.last_query_time[registry]
            if elapsed < self.min_query_interval:
                time.sleep(self.min_query_interval - elapsed)
        self.last_query_time[registry] = time.time()

    def query_ripe(self, ip):
        """Query RIPE database."""
        self._rate_limit('RIPE')
        try:
            params = {
                'query-string': ip,
                'type-filter': 'inetnum',
                'flags': 'no-referenced'
            }
            response = requests.get(
                self.REGISTRY_ENDPOINTS['RIPE'],
                params=params,
                headers={'Accept': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                for obj in data.get('objects', {}).get('object', []):
                    if obj.get('type') == 'inetnum':
                        attributes = obj.get('attributes', {}).get('attribute', [])
                        result = {'registry': 'RIPE'}
                        for attr in attributes:
                            name = attr.get('name')
                            value = attr.get('value')
                            if name and value:
                                result[name] = value
                        return result
        except Exception as e:
            print(f"RIPE query error for {ip}: {str(e)}")
        return None

    def query_arin(self, ip):
        """Query ARIN database."""
        self._rate_limit('ARIN')
        try:
            response = requests.get(
                f"{self.REGISTRY_ENDPOINTS['ARIN']}/{ip}/pft",
                headers={'Accept': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                net = data.get('net', {})
                return {
                    'registry': 'ARIN',
                    'range': f"{net.get('startAddress', '')} - {net.get('endAddress', '')}",
                    'netname': net.get('name', ''),
                    'organization': net.get('orgRef', {}).get('name', ''),
                    'country': net.get('orgRef', {}).get('iso3166-1', {}).get('code2', ''),
                    'cidr': net.get('netBlocks', {}).get('netBlock', [{}])[0].get('cidrLength', '')
                }
        except Exception as e:
            print(f"ARIN query error for {ip}: {str(e)}")
        return None

    def query_rdap(self, ip):
        """Query IP using RDAP protocol."""
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            network = result.get('network', {})
            return {
                'registry': result.get('asn_registry', 'Unknown').upper(),
                'cidr': network.get('cidr'),
                'organization': network.get('name'),
                'country': network.get('country'),
                'range': network.get('range'),
                'netname': network.get('handle')
            }
        except Exception as e:
            print(f"RDAP query error for {ip}: {str(e)}")
        return None

    def get_network_info(self, ip):
        """Get comprehensive network information for an IP."""
        registry = self.determine_registry(ip)
        
        if registry == 'RIPE':
            info = self.query_ripe(ip)
        elif registry == 'ARIN':
            info = self.query_arin(ip)
        else:
            info = self.query_rdap(ip)
            
        if info is None:
            info = self.query_rdap(ip)  # Fallback to RDAP

        if info:
            # Convert range to CIDR if needed
            if 'range' in info and 'cidr' not in info:
                try:
                    if ' - ' in info['range']:
                        start, end = info['range'].split(' - ')
                        start_ip = ipaddress.IPv4Address(start.strip())
                        end_ip = ipaddress.IPv4Address(end.strip())
                        cidrs = list(ipaddress.summarize_address_range(start_ip, end_ip))
                        if cidrs:
                            info['cidr'] = str(cidrs[0])
                except Exception as e:
                    print(f"Error converting range to CIDR: {str(e)}")
        
        return info