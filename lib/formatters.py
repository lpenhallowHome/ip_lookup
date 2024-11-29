#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from datetime import datetime
from .utils import format_threats

class ResultFormatter:
    """
    Handle formatting and display of IP lookup results using Rich.
    """
    
    def __init__(self):
        self.console = Console()

    def create_basic_table(self, results):
        """Create the basic information table."""
        table = Table(
            title="Basic Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("CIDR Range", style="green")
        table.add_column("Forti Name", style="red")
        table.add_column("Organization", style="yellow")
        table.add_column("Country", style="blue")
        table.add_column("Registry", style="magenta")
        
        for result in results:
            table.add_row(
                str(result.get('ip', 'N/A')),
                str(result.get('cidr', 'N/A')),
                str(result.get('forti_name', 'N/A')),
                str(result.get('organization', 'N/A')),
                str(result.get('country', 'N/A')),
                str(result.get('registry', 'N/A'))
            )
        
        return table

    def create_dns_table(self, results):
        """Create the DNS information table."""
        table = Table(
            title="DNS Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Reverse DNS", style="green", width=50)
        table.add_column("Network Name", style="yellow")
        
        for result in results:
            table.add_row(
                str(result.get('ip', 'N/A')),
                str(result.get('reverse_dns', 'N/A')),
                str(result.get('network_name', 'N/A'))
            )
        
        return table

    def format_threat_score(self, score):
        """Format and color-code threat scores."""
        try:
            score_val = float(score)
            if score_val >= 80:
                return f"[red]{score_val:.1f}[/red]"
            elif score_val >= 50:
                return f"[yellow]{score_val:.1f}[/yellow]"
            else:
                return f"[green]{score_val:.1f}[/green]"
        except (ValueError, TypeError):
            return str(score)

    def create_security_table(self, results):
        """Create the security information table."""
        table = Table(
            title="Security Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Threat Score", justify="right")
        table.add_column("AbuseIPDB Score", justify="right")
        table.add_column("VT Detections", justify="right", style="green")
        table.add_column("Last Seen", style="blue")
        table.add_column("ISP", style="yellow")
        
        for result in results:
            sec_info = result.get('security_info')
            
            if sec_info and hasattr(sec_info, 'details'):
                try:
                    # Get threat score
                    threat_score = self.format_threat_score(
                        getattr(sec_info, 'threat_score', 'N/A')
                    )
                    
                    # Get AbuseIPDB info
                    abuse_data = sec_info.details.get('abuseipdb', {}).get('data', {})
                    abuse_score = abuse_data.get('abuseConfidenceScore', 'N/A')
                    if isinstance(abuse_score, (int, float)):
                        abuse_score = self.format_threat_score(abuse_score)
                    isp = abuse_data.get('isp', 'N/A')
                    
                    # Get VirusTotal info
                    vt_data = sec_info.details.get('virustotal', {})
                    vt_stats = vt_data.get('last_analysis_stats', {})
                    if vt_stats:
                        vt_mal = f"{vt_stats.get('malicious', 0)}/{sum(vt_stats.values())}"
                    else:
                        vt_mal = 'N/A'
                    
                    # Get last seen
                    last_seen = getattr(sec_info, 'last_seen', 'N/A')
                    if isinstance(last_seen, datetime):
                        last_seen = last_seen.strftime('%Y-%m-%d')
                    
                    table.add_row(
                        str(result.get('ip', 'N/A')),
                        str(threat_score),
                        str(abuse_score),
                        vt_mal,
                        str(last_seen),
                        str(isp)
                    )
                except Exception as e:
                    table.add_row(
                        str(result.get('ip', 'N/A')),
                        'Error', 'Error', 'Error', 'Error', 'Error'
                    )
            else:
                table.add_row(
                    str(result.get('ip', 'N/A')),
                    'N/A', 'N/A', 'N/A', 'N/A', 'N/A'
                )
        
        return table

    def create_details_table(self, results):
        """Create the detailed information table."""
        table = Table(
            title="Detailed Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Registration Date", style="green")
        table.add_column("Last Updated", style="yellow")
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
        """Create the contact information table."""
        table = Table(
            title="Contact Information",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            title_style="bold blue"
        )
        
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Abuse Contacts", style="red", width=50)
        table.add_column("Remarks", style="yellow", width=50)
        
        for result in results:
            table.add_row(
                str(result.get('ip', 'N/A')),
                str(result.get('abuse_emails', 'N/A')),
                str(result.get('remarks', 'N/A'))
            )
        
        return table

def display_results(results):
    """
    Display formatted results using Rich tables.
    """
    formatter = ResultFormatter()
    console = Console()
    
    try:
        # Create all tables
        basic_table = formatter.create_basic_table(results)
        dns_table = formatter.create_dns_table(results)
        security_table = formatter.create_security_table(results)
        details_table = formatter.create_details_table(results)
        contact_table = formatter.create_contact_table(results)

        # Display all tables with spacing
        console.print()
        console.print(basic_table)
        console.print()
        console.print(dns_table)
        console.print()
        console.print(security_table)
        console.print()
        console.print(details_table)
        console.print()
        console.print(contact_table)
        console.print()
        
    except Exception as e:
        console.print(f"[red]Error displaying results: {str(e)}[/red]")