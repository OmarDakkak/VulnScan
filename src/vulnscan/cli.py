#!/usr/bin/env python3
"""
VulnScan - Ethical Vulnerability Scanner for IP-based Websites
Description: A smart CLI tool for ethical vulnerability assessment and penetration testing
"""

import click
import ipaddress
import sys
import random
import json
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate
from .scanner import VulnerabilityScanner
from .utils import validate_ip, print_banner, print_report
from .web_scanner import WebScanner
from .service_scanner import ServiceScanner
from .database import VulnDatabase

# Initialize colorama for cross-platform colored output
init()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """VulnScan - Smart Ethical Vulnerability Scanner for IP-based Websites
    
    This tool is designed for ethical security assessment only.
    Only scan systems you own or have explicit permission to test.
    """
    print_banner()

@cli.command()
@click.argument('target_ip')
@click.option('--ports', '-p', default='80,443,8080,8443', 
              help='Comma-separated list of ports to scan')
@click.option('--threads', '-t', default=10, 
              help='Number of threads for scanning')
@click.option('--timeout', default=5, 
              help='Connection timeout in seconds')
@click.option('--output', '-o', type=click.Path(), 
              help='Output file to save results')
@click.option('--smart-check', is_flag=True, help='Perform smart vulnerability assessment')
@click.option('--service-scan', is_flag=True, help='Identify service versions and check for known CVEs')
@click.option('--web-scan', is_flag=True, help='Scan for web vulnerabilities if HTTP services are found')
@click.option('--save-db', is_flag=True, help='Save results to database for tracking')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan(target_ip, ports, threads, timeout, output, smart_check, service_scan, web_scan, save_db, verbose):
    """Scan a target IP address for vulnerabilities"""
    
    # Validate IP address
    if not validate_ip(target_ip):
        click.echo(f"{Fore.RED}Error: Invalid IP address format{Style.RESET_ALL}")
        sys.exit(1)
    
    # Parse ports
    try:
        port_list = [int(p.strip()) for p in ports.split(',')]
    except ValueError:
        click.echo(f"{Fore.RED}Error: Invalid port format{Style.RESET_ALL}")
        sys.exit(1)
    
    click.echo(f"{Fore.CYAN}Starting advanced vulnerability scan on {target_ip}{Style.RESET_ALL}")
    click.echo(f"Ports: {ports}")
    click.echo(f"Threads: {threads}")
    click.echo("-" * 50)
    
    # Initialize database if needed
    db = None
    target_id = None
    if save_db:
        db = VulnDatabase()
        target_id = db.add_target(target_ip)
    
    all_results = {}
    
    # Start with basic port scan
    click.echo(f"\n{Fore.CYAN}Phase 1: Basic port and vulnerability scan{Style.RESET_ALL}")
    scanner = VulnerabilityScanner(
        target_ip=target_ip,
        ports=port_list,
        threads=threads,
        timeout=timeout,
        verbose=verbose
    )
    
    try:
        port_results = scanner.run_scan()
        all_results['port_scan'] = port_results
        
        # Display port results
        scanner.display_results(port_results)
        
        if save_db and db and target_id:
            db.add_scan_result(target_id, 'port', port_results)
        
        # Detect open web ports for further scanning
        web_ports = []
        for port, info in port_results.items():
            if info.get('open'):
                if port in [80, 443, 8080, 8443]:
                    web_ports.append(port)
        
        # Service scan if requested
        if service_scan or smart_check:
            open_ports = [port for port, info in port_results.items() if info.get('open')]
            if open_ports:
                click.echo(f"\n{Fore.CYAN}Phase 2: Service identification and CVE checking{Style.RESET_ALL}")
                service_scanner = ServiceScanner(target_ip, open_ports, timeout)
                service_results = service_scanner.run_scan()
                all_results['service_scan'] = service_results
                
                # Display service information
                if 'services' in service_results:
                    services = service_results['services']
                    if services:
                        click.echo("\nDetected Services:")
                        table = []
                        for port, info in services.items():
                            table.append([
                                port,
                                info.get('service', 'unknown'),
                                info.get('version', 'unknown'),
                                (info.get('banner', '') or '')[:50]
                            ])
                        print(tabulate(table, headers=["Port", "Service", "Version", "Banner"]))
                
                # Display vulnerabilities
                if 'vulnerabilities' in service_results:
                    vulns = service_results['vulnerabilities']
                    if vulns:
                        click.echo(f"\n{Fore.RED}Found {len(vulns)} potential CVE vulnerabilities:{Style.RESET_ALL}")
                        table = []
                        for vuln in vulns:
                            table.append([
                                vuln.get('cve_id', 'Unknown'),
                                vuln.get('severity', 'Unknown'),
                                vuln.get('score', 0.0),
                                (vuln.get('description', '') or '')[:70]
                            ])
                        print(tabulate(table, headers=["CVE ID", "Severity", "CVSS", "Description"]))
                
                if save_db and db and target_id:
                    db.add_scan_result(target_id, 'service', service_results)
        
        # Web scan if requested and web ports found
        if (web_scan or smart_check) and web_ports:
            click.echo(f"\n{Fore.CYAN}Phase 3: Web vulnerability scanning{Style.RESET_ALL}")
            
            for port in web_ports:
                click.echo(f"\nScanning web service on port {port}...")
                web_scanner = WebScanner(target_ip, threads=threads, timeout=timeout)
                web_results = web_scanner.run_scan()
                all_results[f'web_scan_port_{port}'] = web_results
                
                # Display results summary
                click.echo(f"Crawled {web_results.get('crawled_urls', 0)} URLs")
                
                xss_vulns = web_results.get('xss_vulnerabilities', [])
                if xss_vulns:
                    click.echo(f"{Fore.RED}Found {len(xss_vulns)} potential XSS vulnerabilities{Style.RESET_ALL}")
                
                sql_vulns = web_results.get('sql_vulnerabilities', [])
                if sql_vulns:
                    click.echo(f"{Fore.RED}Found {len(sql_vulns)} potential SQL Injection vulnerabilities{Style.RESET_ALL}")
                
                # Display detailed results if verbose
                if verbose:
                    if xss_vulns:
                        click.echo("\nXSS Vulnerabilities:")
                        table = []
                        for vuln in xss_vulns:
                            table.append([
                                vuln.get('url', ''),
                                vuln.get('method', 'GET'),
                                vuln.get('param', ''),
                                vuln.get('evidence', '')
                            ])
                        print(tabulate(table, headers=["URL", "Method", "Parameter", "Evidence"]))
                    
                    if sql_vulns:
                        click.echo("\nSQL Injection Vulnerabilities:")
                        table = []
                        for vuln in sql_vulns:
                            table.append([
                                vuln.get('url', ''),
                                vuln.get('method', 'GET'),
                                vuln.get('param', ''),
                                vuln.get('evidence', '')
                            ])
                        print(tabulate(table, headers=["URL", "Method", "Parameter", "Evidence"]))
                
                if save_db and db and target_id:
                    db.add_scan_result(target_id, 'web', web_results)
        
        # Save to file if requested
        if output:
            with open(output, 'w') as f:
                json.dump(all_results, f, indent=2)
            click.echo(f"\n{Fore.GREEN}Results saved to {output}{Style.RESET_ALL}")
        
        # Final summary and recommendations
        if smart_check:
            print_report(all_results)
            
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        click.echo(f"{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        if db:
            db.close()

@cli.command()
@click.option('--subnet', default='192.168.1.0/24', help='Subnet to scan in CIDR notation')
@click.option('--random', 'random_ips', is_flag=True, help='Scan random public IP addresses')
@click.option('--count', default=10, help='Number of random IPs to scan')
@click.option('--ports', '-p', default='80,443,8080,8443', help='Comma-separated list of ports to scan')
@click.option('--threads', '-t', default=10, help='Number of threads for scanning')
@click.option('--timeout', default=5, help='Connection timeout in seconds')
@click.option('--smart-check', is_flag=True, help='Perform smart vulnerability assessment')
@click.option('--service-scan', is_flag=True, help='Identify service versions and check for CVEs')
@click.option('--output', '-o', type=click.Path(), help='Output file to save results')
@click.option('--save-db', is_flag=True, help='Save results to database for tracking')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def auto_scan(subnet, random_ips, count, ports, threads, timeout, smart_check, 
              service_scan, output, save_db, verbose):
    """Automatically scan a subnet or random IPs for vulnerabilities"""
    
    # Initialize database if needed
    db = None
    if save_db:
        db = VulnDatabase()
    
    # Generate IP list
    if random_ips:
        click.echo(f"{Fore.CYAN}Auto-scanning {count} random public IP addresses{Style.RESET_ALL}")
        ip_list = []
        while len(ip_list) < count:
            ip = '.'.join(str(random.randint(1, 254)) for _ in range(4))
            # Exclude private/reserved ranges
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_loopback):
                    ip_list.append(ip)
            except Exception:
                continue
    else:
        click.echo(f"{Fore.CYAN}Auto-scanning subnet: {subnet}{Style.RESET_ALL}")
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        except Exception as e:
            click.echo(f"{Fore.RED}Invalid subnet: {e}{Style.RESET_ALL}")
            sys.exit(1)
            
    click.echo(f"Scanning {len(ip_list)} IP addresses...")
    
    # Parse ports
    try:
        port_list = [int(p.strip()) for p in ports.split(',')]
    except ValueError:
        click.echo(f"{Fore.RED}Error: Invalid port format{Style.RESET_ALL}")
        sys.exit(1)
        
    # Results tracking
    all_results = {}
    valid_ips = []
    vulnerable_ips = []
    
    for i, ip in enumerate(ip_list, 1):
        click.echo(f"\n{Fore.CYAN}[{i}/{len(ip_list)}] Scanning {ip}{Style.RESET_ALL}")
        
        # Save target to database
        target_id = None
        if db:
            target_id = db.add_target(ip)
        
        # Basic port scan
        scanner = VulnerabilityScanner(
            target_ip=ip,
            ports=port_list,
            threads=threads,
            timeout=timeout,
            verbose=verbose
        )
        
        try:
            port_results = scanner.run_scan()
            all_results[ip] = {'port_scan': port_results}
            
            # Check if any port is open
            has_open_ports = any(res.get('open') for res in port_results.values())
            
            if has_open_ports:
                valid_ips.append(ip)
                
                # Check for vulnerabilities
                has_vulnerabilities = any(
                    res.get('open') and res.get('vulnerabilities') 
                    for res in port_results.values()
                )
                
                if has_vulnerabilities:
                    vulnerable_ips.append(ip)
                
                # Display basic results
                if verbose:
                    scanner.display_results(port_results)
                else:
                    open_ports = [port for port, res in port_results.items() if res.get('open')]
                    click.echo(f"Open ports: {', '.join(str(p) for p in open_ports)}")
                
                # Save port scan results to database
                if db and target_id:
                    db.add_scan_result(target_id, 'port', port_results)
                
                # Detect open web ports for further scanning
                web_ports = [
                    port for port, info in port_results.items() 
                    if info.get('open') and port in [80, 443, 8080, 8443]
                ]
                
                # Service scanning
                if (service_scan or smart_check) and has_open_ports:
                    open_ports = [port for port, info in port_results.items() if info.get('open')]
                    if open_ports:
                        click.echo("Performing service fingerprinting...")
                        service_scanner = ServiceScanner(ip, open_ports, timeout)
                        service_results = service_scanner.run_scan()
                        all_results[ip]['service_scan'] = service_results
                        
                        # Check for CVE vulnerabilities
                        if 'vulnerabilities' in service_results and service_results['vulnerabilities']:
                            vulnerable_ips.append(ip)
                            if verbose:
                                click.echo(f"{Fore.RED}Found {len(service_results['vulnerabilities'])} potential CVE vulnerabilities{Style.RESET_ALL}")
                        
                        # Save to database
                        if db and target_id:
                            db.add_scan_result(target_id, 'service', service_results)
                
                # Smart web scanning for web ports
                if (smart_check) and web_ports:
                    click.echo("Performing web vulnerability scanning...")
                    for port in web_ports[:1]:  # Just scan the first web port for auto-scan
                        web_scanner = WebScanner(ip, threads=threads, timeout=timeout)
                        web_results = web_scanner.run_scan()
                        all_results[ip][f'web_scan_port_{port}'] = web_results
                        
                        # Check for web vulnerabilities
                        has_web_vulns = (
                            web_results.get('xss_vulnerabilities', []) or 
                            web_results.get('sql_vulnerabilities', [])
                        )
                        
                        if has_web_vulns:
                            vulnerable_ips.append(ip)
                            if verbose:
                                vuln_count = (
                                    len(web_results.get('xss_vulnerabilities', [])) +
                                    len(web_results.get('sql_vulnerabilities', []))
                                )
                                click.echo(f"{Fore.RED}Found {vuln_count} web vulnerabilities{Style.RESET_ALL}")
                        
                        # Save to database
                        if db and target_id:
                            db.add_scan_result(target_id, 'web', web_results)
            
        except Exception as e:
            click.echo(f"{Fore.RED}Error scanning {ip}: {str(e)}{Style.RESET_ALL}")
            all_results[ip] = {"error": str(e)}
    
    # Ensure uniqueness of IPs in lists
    valid_ips = list(set(valid_ips))
    vulnerable_ips = list(set(vulnerable_ips))
    
    # Log valid IPs to file
    if valid_ips:
        with open('valid_ips.txt', 'w') as f:
            for ip in valid_ips:
                f.write(f"{ip}\n")
        click.echo(f"\n{Fore.GREEN}Logged {len(valid_ips)} valid IPs to valid_ips.txt{Style.RESET_ALL}")
    
    # Log vulnerable IPs to file
    if vulnerable_ips:
        with open('vulnerable_ips.txt', 'w') as f:
            for ip in vulnerable_ips:
                f.write(f"{ip}\n")
        click.echo(f"{Fore.RED}Logged {len(vulnerable_ips)} vulnerable IPs to vulnerable_ips.txt{Style.RESET_ALL}")
    
    # Summary
    click.echo(f"\n{Fore.GREEN}Auto-scan completed!{Style.RESET_ALL}")
    click.echo(f"Scanned {len(ip_list)} targets")
    click.echo(f"Found {len(valid_ips)} responsive IPs")
    click.echo(f"Found {len(vulnerable_ips)} potentially vulnerable IPs")
    
    # Save to file if requested
    if output:
        with open(output, 'w') as f:
            json.dump(all_results, f, indent=2)
        click.echo(f"Full results saved to {output}")
    
    # Close database connection
    if db:
        db.close()

@cli.command()
@click.option('--ip', help='Show report for specific IP')
@click.option('--format', 'report_format', type=click.Choice(['text', 'json']), default='text',
              help='Report format (text or json)')
@click.option('--output', '-o', type=click.Path(), help='Save report to file')
def reports(ip, report_format, output):
    """Generate vulnerability reports from the database"""
    db = VulnDatabase()
    
    try:
        if ip:
            # Report for specific IP
            history = db.get_target_history(ip)
            
            if not history:
                click.echo(f"{Fore.RED}No data found for IP {ip}{Style.RESET_ALL}")
                sys.exit(1)
            
            if report_format == 'text':
                click.echo(f"\n{Fore.CYAN}Vulnerability Report for {ip}{Style.RESET_ALL}")
                click.echo("-" * 60)
                
                # Show scan history
                click.echo(f"\n{Fore.YELLOW}Scan History:{Style.RESET_ALL}")
                for scan in history['scans']:
                    click.echo(f"  - {scan['time']}: {scan['type']} scan")
                
                # Show vulnerabilities
                click.echo(f"\n{Fore.YELLOW}Vulnerabilities:{Style.RESET_ALL}")
                if history['vulnerabilities']:
                    table = []
                    for vuln in history['vulnerabilities']:
                        table.append([
                            vuln['type'],
                            vuln['severity'],
                            vuln['score'],
                            vuln['description'][:50],
                            vuln['status']
                        ])
                    print(tabulate(table, headers=["Type", "Severity", "CVSS", "Description", "Status"]))
                else:
                    click.echo("  No vulnerabilities found.")
            else:
                # JSON format
                report_data = {
                    'ip': ip,
                    'report_time': datetime.now().isoformat(),
                    'history': history
                }
                
                if output:
                    with open(output, 'w') as f:
                        json.dump(report_data, f, indent=2)
                    click.echo(f"Report saved to {output}")
                else:
                    print(json.dumps(report_data, indent=2))
        else:
            # General stats report
            stats = db.get_vulnerability_stats()
            scans = db.get_recent_scans(10)
            
            if report_format == 'text':
                click.echo(f"\n{Fore.CYAN}VulnScan Summary Report{Style.RESET_ALL}")
                click.echo("-" * 60)
                
                click.echo(f"\n{Fore.YELLOW}Recent Scans:{Style.RESET_ALL}")
                if scans:
                    table = []
                    for scan in scans:
                        table.append([
                            scan['ip_address'],
                            scan['time'],
                            scan['type'],
                            scan['vulnerability_count']
                        ])
                    print(tabulate(table, headers=["IP", "Time", "Type", "Vulnerabilities"]))
                else:
                    click.echo("  No recent scans.")
                
                click.echo(f"\n{Fore.YELLOW}Vulnerability Statistics:{Style.RESET_ALL}")
                click.echo("By Severity:")
                for severity, count in stats['by_severity'].items():
                    click.echo(f"  - {severity}: {count}")
                
                click.echo("\nTop Vulnerability Types:")
                for vuln_type, count in stats['by_type'].items():
                    click.echo(f"  - {vuln_type}: {count}")
            else:
                # JSON format
                report_data = {
                    'report_time': datetime.now().isoformat(),
                    'recent_scans': scans,
                    'stats': stats
                }
                
                if output:
                    with open(output, 'w') as f:
                        json.dump(report_data, f, indent=2)
                    click.echo(f"Report saved to {output}")
                else:
                    print(json.dumps(report_data, indent=2))
    finally:
        db.close()

def main():
    """Entry point for the CLI"""
    cli()

if __name__ == '__main__':
    main()