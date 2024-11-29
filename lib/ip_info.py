#!/usr/bin/env python3

import socket
import time
from datetime import datetime
from .registry_lookup import RegistryLookup
from .utils import safe_get

class IPInfo:
    """
    Core IP information gathering class.
    """
    
    def __init__(self):
        self.registry_lookup = RegistryLookup()
        self.cache = {}
        
    def get_forti_name(self, cidr):
        """
        Convert CIDR range to Fortinet-style name.
        """
        if not cidr or cidr in ('Not Found', 'Error'):
            return 'Not Found'
            
        try:
            ip = cidr.split('/')[0]
            octets = ip.split('.')
            
            for i, octet in enumerate(octets):
                if octet == '0':
                    return f"dodgy-src-{'.'.join(octets[:i])}"
            
            return f"dodgy-src-{'.'.join(octets[:3])}"
        except Exception as e:
            print(f"Error creating Forti name: {str(e)}")
            return "Error parsing CIDR"

    def reverse_dns_lookup(self, ip):
        """
        Perform a reverse DNS lookup for an IP address.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "No PTR record"

    def get_security_info(self, ip, security_monitor):
        """
        Get security information using SecurityAPIMonitor.
        """
        try:
            results = security_monitor.query_batch([ip])
            if results and len(results) > 0:
                return results[0]
        except Exception as e:
            print(f"Error getting security info for {ip}: {str(e)}")
        return None

    def merge_ip_info(self, registry_info, rdap_info):
        """
        Merge information from different sources with registry info taking precedence.
        """
        merged = {
            'cidr': safe_get(registry_info, 'cidr'),
            'organization': safe_get(registry_info, 'organization'),
            'country': safe_get(registry_info, 'country'),
            'network_name': safe_get(registry_info, 'netname'),
            'status': safe_get(registry_info, 'status'),
            'registry': safe_get(registry_info, 'registry', default='Unknown')
        }

        # Fill in missing information from RDAP if available
        if rdap_info:
            network = rdap_info.get('network', {})
            if not merged['cidr']:
                merged['cidr'] = network.get('cidr')
            if not merged['organization']:
                merged['organization'] = network.get('name')
            if not merged['country']:
                merged['country'] = network.get('country')
            if not merged['network_name']:
                merged['network_name'] = network.get('handle')
            if not merged['status']:
                status = network.get('status', [])
                if isinstance(status, list) and status:
                    merged['status'] = ', '.join(status)

            # Extract remarks
            merged['remarks'] = []
            remarks = network.get('remarks', [])
            if isinstance(remarks, list):
                for remark in remarks:
                    if isinstance(remark, dict):
                        desc = remark.get('description', [])
                        if isinstance(desc, list) and desc:
                            merged['remarks'].append(str(desc[0]))
            merged['remarks'] = '; '.join(merged['remarks']) if merged['remarks'] else 'Not Found'

            # Extract dates
            events = rdap_info.get('events', [])
            for event in events:
                if isinstance(event, dict):
                    action = event.get('action')
                    timestamp = event.get('timestamp')
                    if action == 'registration':
                        merged['registration_date'] = timestamp
                    elif action == 'last changed':
                        merged['last_updated'] = timestamp

            # Extract abuse contacts
            abuse_emails = set()
            entities = rdap_info.get('entities', [])
            if isinstance(entities, list):
                for entity in entities:
                    if isinstance(entity, dict):
                        roles = entity.get('roles', [])
                        if 'abuse' in roles:
                            contact = entity.get('contact', {})
                            emails = contact.get('email', [])
                            for email in emails:
                                if isinstance(email, dict):
                                    email_value = email.get('value')
                                    if email_value:
                                        abuse_emails.add(str(email_value))
            merged['abuse_emails'] = ', '.join(abuse_emails) if abuse_emails else 'Not Found'

        # Set default values for missing fields
        for field in ['cidr', 'organization', 'country', 'network_name', 'status', 
                     'remarks', 'registration_date', 'last_updated', 'abuse_emails']:
            if field not in merged or not merged[field]:
                merged[field] = 'Not Found'

        return merged

    def get_ip_info(self, ip_address, security_monitor=None):
        """
        Get comprehensive IP information from all sources.
        """
        info = {
            'ip': ip_address,
            'reverse_dns': 'Not Found',
            'forti_name': 'Not Found',
            'security_info': None
        }

        try:
            # Get reverse DNS
            info['reverse_dns'] = self.reverse_dns_lookup(ip_address)

            # Get registry information
            registry_info = self.registry_lookup.get_network_info(ip_address)

            # Merge information from different sources
            merged_info = self.merge_ip_info(registry_info or {}, {})
            info.update(merged_info)

            # Create Forti name if we have a CIDR
            if info['cidr'] != 'Not Found':
                info['forti_name'] = self.get_forti_name(info['cidr'])

            # Get security information if monitor is provided
            if security_monitor:
                info['security_info'] = self.get_security_info(ip_address, security_monitor)

        except Exception as e:
            print(f"Error processing IP {ip_address}: {str(e)}")

        return info

# Initialize a global instance
ip_info = IPInfo()

def get_ip_info(ip_address, security_monitor=None):
    """
    Global function to get IP information using the global IPInfo instance.
    """
    return ip_info.get_ip_info(ip_address, security_monitor)