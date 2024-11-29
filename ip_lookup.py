#!/usr/bin/env python3

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from security_monitor import SecurityAPIMonitor
from lib.ip_info import get_ip_info
from lib.formatters import display_results

def setup_argparse():
    parser = argparse.ArgumentParser(
        description='Comprehensive IP Information Lookup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Check a single IP:
    python ip_lookup.py -i 8.8.8.8

    # Check multiple IPs:
    python ip_lookup.py -i 8.8.8.8 8.8.4.4 1.1.1.1

    # Check IPs from file:
    python ip_lookup.py -f ip_list.txt
    """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ips', nargs='+', metavar='IP',
                      help='One or more IP addresses to lookup')
    group.add_argument('-f', '--file', metavar='FILE',
                      help='File containing list of IPs (one per line)')
    
    parser.add_argument('-w', '--workers', type=int, default=2,
                      help='Number of concurrent workers (default: 2, max: 5)')
    
    return parser

def read_ip_list(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        sys.exit(1)

def process_ips_parallel(ips, security_monitor, max_workers=2):
    results = []
    max_workers = min(max_workers, 5)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(get_ip_info, ip, security_monitor): ip
            for ip in ips
        }

        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing IP {ip}: {str(e)}")

    return results

def main():
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # Initialize security monitor (now uses environment variables)
        security_monitor = SecurityAPIMonitor()

        # Get list of IPs to process
        if args.ips:
            ip_list = args.ips
        else:
            ip_list = read_ip_list(args.file)

        if not ip_list:
            print("No IP addresses to process.")
            sys.exit(1)

        print(f"Processing {len(ip_list)} IP addresses...")

        # Process IPs
        results = process_ips_parallel(
            ip_list,
            security_monitor,
            max_workers=args.workers
        )

        # Display results
        if results:
            display_results(results)
        else:
            print("No results found.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()