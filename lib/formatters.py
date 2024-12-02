# File: /stuff/laura/gitlab/infosec_ip_lookup/lib/formatters.py

#!/usr/bin/env python

from rich.console import Console
from rich.table import Table
from datetime import datetime

class ResultFormatter:
    """
    Handle formatting and display of IP lookup results using Rich.
    """
    
    def __init__(self):
        self.console = Console()

    def _process_forti(self, result, ip, cidr, seen_network_cidrs, seen_forti_names):
        """
        Helper method to process Forti names and network CIDRs based on abuse score
        """
        network_cidr = 'N/A'
        forti_name = 'N/A'
        
        if cidr != 'N/A' and ip != 'N/A':
            try:
                # Get AbuseIPDB score first
                sec_info = result.get('security_info')
                abuse_score = 0
                if sec_info and hasattr(sec_info, 'details'):
                    abuse_data = sec_info.details.get('abuseipdb', {}).get('data', {})
                    abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                
                # Only process if abuse score is >= 10
                if abuse_score >= 10:
                    cidr_parts = cidr.split('/')
                    if len(cidr_parts) >= 2:
                        prefix = int(cidr_parts[-1])
                        ip_parts = ip.split('.')
                        
                        if len(ip_parts) == 4:
                            if prefix < 24:
                                network_cidr = f"{'.'.join(ip_parts[:3])}.0/24"
                                forti_name = f"dodgy-src-{'.'.join(ip_parts[:3])}"
                            else:
                                network_cidr = cidr
                                forti_name = str(result.get('forti_name', 'N/A'))
                        else:
                            self.console.print(f"[yellow]Warning: Invalid IP format: {ip}[/yellow]")
                    else:
                        self.console.print(f"[yellow]Warning: Invalid CIDR format: {cidr}[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error creating Forti name for IP {ip} with CIDR {cidr}: {str(e)}[/red]")
                network_cidr = 'N/A'
                forti_name = 'N/A'

        # Check for duplicates
        if network_cidr in seen_network_cidrs:
            network_cidr = "already captured"
        elif network_cidr != 'N/A':
            seen_network_cidrs.add(network_cidr)

        if forti_name in seen_forti_names:
            forti_name = "already captured"
        elif forti_name != 'N/A':
            seen_forti_names.add(forti_name)
            
        return network_cidr, forti_name

    def create_basic_table(self, results):
        """
        Create the basic information table.
        """
        table = Table(
            title="Basic Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP\nAddress", style="cyan", no_wrap=True)
        table.add_column("CIDR\nRange", style="green")
        table.add_column("Network\nCIDR", style="green")
        table.add_column("Forti\nName", style="red")
        table.add_column("Organization", style="yellow")
        table.add_column("Country", style="blue")
        table.add_column("Registry", style="magenta")
        
        seen_forti_names = set()
        seen_network_cidrs = set()
        
        for result in results:
            ip = str(result.get('ip', 'N/A'))
            cidr = str(result.get('cidr', 'N/A'))
            
            network_cidr, forti_name = self._process_forti(
                result, ip, cidr, seen_network_cidrs, seen_forti_names
            )

            table.add_row(
                ip,
                cidr,
                network_cidr,
                forti_name,
                str(result.get('organization', 'N/A')),
                str(result.get('country', 'N/A')),
                str(result.get('registry', 'N/A'))
            )
        
        return table

    def create_dns_table(self, results):
        """
        Create the DNS information table.
        """
        table = Table(
            title="DNS Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP\nAddress", style="cyan", no_wrap=True)
        table.add_column("Reverse\nDNS", style="green")
        table.add_column("Network\nName", style="yellow")
        
        for result in results:
            table.add_row(
                str(result.get('ip', 'N/A')),
                str(result.get('reverse_dns', 'N/A')),
                str(result.get('network_name', 'N/A'))
            )
        
        return table

    def format_threat_score(self, score):
        """
        Format and color-code threat scores.
        """
        if not isinstance(score, (int, float)) or score == 'N/A':
            return 'N/A'
        
        if score >= 80:
            return f"[red]{score:.1f}[/red]"
        elif score >= 50:
            return f"[yellow]{score:.1f}[/yellow]"
        else:
            return f"[green]{score:.1f}[/green]"

    def create_details_table(self, results):
        """
        Create the detailed information table.
        """
        table = Table(
            title="Detailed Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP\nAddress", style="cyan", no_wrap=True)
        table.add_column("Registration\nDate", style="green")
        table.add_column("Last\nUpdated", style="yellow")
        table.add_column("Type", style="blue")
        table.add_column("Status", style="magenta")
        
        for result in results:
            table.add_row(
                str(result.get('ip', 'N/A')),
                str(result.get('registration_date', 'N/A')),
                str(result.get('last_updated', 'N/A')),
                str(result.get('type', 'N/A')),
                str(result.get('status', 'N/A'))
            )
        
        return table

    def create_contact_table(self, results):
        """
        Create the contact information table.
        """
        table = Table(
            title="Contact Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP\nAddress", style="cyan", no_wrap=True)
        table.add_column("Abuse\nContacts", style="red")
        table.add_column("Remarks", style="yellow")
        
        for result in results:
            table.add_row(
                str(result.get('ip', 'N/A')),
                str(result.get('abuse_emails', 'N/A')),
                str(result.get('remarks', 'N/A'))
            )
        
        return table

    def display_results(self, results):
        """
        Display formatted results using Rich tables.
        """
        try:
            # Create all tables
            basic_table = self.create_basic_table(results)
            dns_table = self.create_dns_table(results)
            details_table = self.create_details_table(results)
            contact_table = self.create_contact_table(results)
            
            # Create combined table
            combined_table = Table(
                title="Combined Basic and Security Information",
                show_header=True,
                header_style="bold magenta",
                show_lines=True,
                title_style="bold blue"
            )
            
            # Add all columns with stacked headers
            combined_table.add_column("IP\nAddress", style="cyan", no_wrap=True)
            combined_table.add_column("CIDR\nRange", style="green")
            combined_table.add_column("Forti\nCIDR", style="green")
            combined_table.add_column("Forti\nName", style="red")
            combined_table.add_column("Organization", style="yellow")
            combined_table.add_column("Country", style="blue")
            combined_table.add_column("Registry", style="magenta")
            combined_table.add_column("Threat\nScore", justify="right")
            combined_table.add_column("Abuse\nScore", justify="right")
            combined_table.add_column("VT\nDetections", justify="right", style="green")
            combined_table.add_column("Last\nSeen", style="blue")
            combined_table.add_column("ISP", style="yellow")
            
            # Keep track of seen values
            seen_forti_names = set()
            seen_network_cidrs = set()
            
            # Add rows with combined information
            for result in results:
                ip = str(result.get('ip', 'N/A'))
                cidr = str(result.get('cidr', 'N/A'))
                
                network_cidr, forti_name = self._process_forti(
                    result, ip, cidr, seen_network_cidrs, seen_forti_names
                )

                # Process security information
                sec_info = result.get('security_info')
                threat_score = 'N/A'
                abuse_score = 'N/A'
                vt_mal = 'N/A'
                last_seen = 'N/A'
                isp = 'N/A'
                
                if sec_info and hasattr(sec_info, 'details'):
                    try:
                        # Get threat score
                        threat_score = self.format_threat_score(
                            getattr(sec_info, 'threat_score', 'N/A')
                        )
                        
                        # Get AbuseIPDB info
                        abuse_data = sec_info.details.get('abuseipdb', {}).get('data', {})
                        abuse_score_val = abuse_data.get('abuseConfidenceScore', 'N/A')
                        if isinstance(abuse_score_val, (int, float)):
                            abuse_score = self.format_threat_score(abuse_score_val)
                        isp = abuse_data.get('isp', 'N/A')
                        
                        # Get VirusTotal info
                        vt_data = sec_info.details.get('virustotal', {})
                        vt_stats = vt_data.get('last_analysis_stats', {})
                        vt_mal = f"{vt_stats.get('malicious', 0)}/{vt_stats.get('total', 0)}"
                        
                        # Get last seen
                        last_seen = getattr(sec_info, 'last_seen', 'N/A')
                        if isinstance(last_seen, datetime):
                            last_seen = last_seen.strftime('%Y-%m-%d')
                    except Exception as e:
                        self.console.print(f"[red]Error processing security info for IP {ip}: {str(e)}[/red]")

                combined_table.add_row(
                    ip,
                    cidr,
                    network_cidr,
                    forti_name,
                    str(result.get('organization', 'N/A')),
                    str(result.get('country', 'N/A')),
                    str(result.get('registry', 'N/A')),
                    str(threat_score),
                    str(abuse_score),
                    vt_mal,
                    str(last_seen),
                    str(isp)
                )

            # Display tables in desired order
            self.console.print()
            self.console.print(basic_table)
            self.console.print()
            self.console.print(dns_table)
            self.console.print()
            self.console.print(details_table)
            self.console.print()
            self.console.print(contact_table)
            self.console.print()
            self.console.print(combined_table)
            self.console.print()
            
        except Exception as e:
            self.console.print(f"[red]Error displaying results: {str(e)}[/red]")