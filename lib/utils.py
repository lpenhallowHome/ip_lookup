#!/usr/bin/env python3

import ipaddress
from datetime import datetime

def safe_get(d, *keys, default='Not Found'):
    """
    Safely get nested dictionary values.
    
    Args:
        d: The dictionary to search in
        *keys: Keys to traverse
        default: Default value if key doesn't exist
    """
    try:
        for key in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(key, default)
        return d if d is not None else default
    except Exception:
        return default

def validate_ip(ip):
    """Validate if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def format_datetime(dt, format='%Y-%m-%d %H:%M:%S'):
    """Format datetime object or string consistently."""
    try:
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        if isinstance(dt, datetime):
            return dt.strftime(format)
    except Exception:
        pass
    return 'Not Found'

def convert_range_to_cidr(range_str):
    """Convert IP range string to CIDR notation."""
    try:
        if ' - ' in range_str:
            start, end = range_str.split(' - ')
            start_ip = ipaddress.IPv4Address(start.strip())
            end_ip = ipaddress.IPv4Address(end.strip())
            cidrs = list(ipaddress.summarize_address_range(start_ip, end_ip))
            return str(cidrs[0]) if cidrs else None
        return str(ipaddress.ip_network(range_str, strict=False))
    except Exception:
        return None

def is_private_ip(ip):
    """Check if IP address is private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def format_threats(abuse_score=None, vt_detections=None):
    """Format threat information consistently."""
    threats = []
    
    if abuse_score is not None and abuse_score != 'N/A':
        try:
            score = float(abuse_score)
            if score >= 80:
                threats.append(f"AbuseIPDB: {score}% (High)")
            elif score >= 50:
                threats.append(f"AbuseIPDB: {score}% (Medium)")
            elif score > 0:
                threats.append(f"AbuseIPDB: {score}% (Low)")
        except (ValueError, TypeError):
            pass

    if vt_detections is not None and vt_detections != 'N/A':
        if isinstance(vt_detections, int) and vt_detections > 0:
            threats.append(f"VT Detections: {vt_detections}")

    return ", ".join(threats) if threats else "None"

def truncate_string(s, max_length=50, suffix='...'):
    """Truncate string to specified length."""
    if len(s) <= max_length:
        return s
    return s[:max_length-len(suffix)] + suffix

def get_date_string(date_val):
    """Convert various date formats to consistent string."""
    if not date_val or date_val == 'Not Found':
        return 'Not Found'
        
    try:
        if isinstance(date_val, str):
            if 'T' in date_val:
                # ISO format
                dt = datetime.fromisoformat(date_val.replace('Z', '+00:00'))
            else:
                # Try various formats
                for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y%m%d']:
                    try:
                        dt = datetime.strptime(date_val, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return date_val
        elif isinstance(date_val, datetime):
            dt = date_val
        else:
            return str(date_val)
            
        return dt.strftime('%Y-%m-%d')
    except Exception:
        return str(date_val)

def merge_dicts(dict1, dict2, prefer_dict1=True):
    """
    Merge two dictionaries with preference handling.
    """
    result = dict2.copy()
    for key, value in dict1.items():
        if prefer_dict1 or key not in result or not result[key]:
            result[key] = value
    return result

def clean_rdap_response(response):
    """Clean and normalize RDAP response data."""
    if not isinstance(response, dict):
        return {}
        
    cleaned = {}
    
    # Extract network information
    if 'network' in response:
        network = response['network']
        cleaned.update({
            'cidr': network.get('cidr', 'Not Found'),
            'name': network.get('name', 'Not Found'),
            'organization': network.get('name', 'Not Found'),
            'type': network.get('type', 'Not Found'),
            'country': network.get('country', 'Not Found')
        })
        
        # Clean status
        status = network.get('status', [])
        if isinstance(status, list):
            cleaned['status'] = ', '.join(status)
        else:
            cleaned['status'] = str(status)
            
    return cleaned