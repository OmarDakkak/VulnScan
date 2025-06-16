"""
utils.py - Utility functions for VulnScan
"""
import ipaddress
import requests
import socket
from datetime import datetime
from colorama import Fore, Style
from tabulate import tabulate

def validate_ip(ip: str) -> bool:
    """Validate if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def print_banner():
    """Print the application banner"""
    print(f"{Fore.GREEN}=== VulnScan - Ethical Vulnerability Scanner ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use only on systems you own or have permission to test!{Style.RESET_ALL}")

def check_http(ip: str, port: int) -> bool:
    """Check if an HTTP or HTTPS service is running on the given IP and port"""
    try:
        scheme = "http"
        if port in (443, 8443):
            scheme = "https"
        url = f"{scheme}://{ip}:{port}/"
        resp = requests.get(url, timeout=3, verify=False)
        return resp.status_code < 500
    except Exception:
        return False

def check_directory_listing(ip: str, port: int) -> bool:
    """Check for directory listing vulnerability"""
    try:
        scheme = "http"
        if port in (443, 8443):
            scheme = "https"
        url = f"{scheme}://{ip}:{port}/"
        resp = requests.get(url, timeout=3, verify=False)
        if "Index of /" in resp.text:
            return True
    except Exception:
        pass
    return False

def check_default_creds(ip: str, port: int) -> bool:
    """Check for default credentials vulnerability"""
    common_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
        ('user', 'user'),
        ('guest', 'guest')
    ]
    
    try:
        for username, password in common_creds:
            # This is a placeholder - real implementation would use HTTP Basic Auth
            # or form-based authentication depending on the service
            pass
    except Exception:
        pass
    
    return False

def categorize_severity(results):
    """Categorize findings by severity"""
    severity = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    # Check port scan results
    if 'port_scan' in results:
        for port, info in results['port_scan'].items():
            if info.get('open') and info.get('vulnerabilities'):
                for vuln in info['vulnerabilities']:
                    if 'Directory listing' in vuln:
                        severity['medium'] += 1
                    elif 'Default credentials' in vuln:
                        severity['high'] += 1
                    else:
                        severity['info'] += 1
    
    # Check service scan results
    if 'service_scan' in results and 'vulnerabilities' in results['service_scan']:
        for vuln in results['service_scan']['vulnerabilities']:
            sev = vuln.get('severity', '').lower()
            if sev in severity:
                severity[sev] += 1
            else:
                severity['info'] += 1
    
    # Check web scan results
    for key, value in results.items():
        if key.startswith('web_scan_port_'):
            if 'xss_vulnerabilities' in value:
                severity['high'] += len(value['xss_vulnerabilities'])
            if 'sql_vulnerabilities' in value:
                severity['critical'] += len(value['sql_vulnerabilities'])
    
    return severity

def generate_recommendations(results):
    """Generate security recommendations based on scan results"""
    recommendations = []
    
    # Basic port recommendations
    if 'port_scan' in results:
        open_ports = [
            port for port, info in results['port_scan'].items()
            if info.get('open')
        ]
        if open_ports:
            recommendations.append(f"Close unnecessary ports. Currently open: {', '.join(map(str, open_ports))}")
    
    # Service-specific recommendations
    if 'service_scan' in results and 'services' in results['service_scan']:
        for port, info in results['service_scan']['services'].items():
            service = info.get('service')
            version = info.get('version')
            
            if service == 'http' and version:
                recommendations.append(f"Update web server on port {port} to latest version")
            
            if service == 'ssh' and port == 22:
                recommendations.append("Consider changing SSH from default port 22 to reduce automated attacks")
    
    # Vulnerability-specific recommendations
    if 'service_scan' in results and 'vulnerabilities' in results['service_scan']:
        cve_count = len(results['service_scan']['vulnerabilities'])
        if cve_count > 0:
            recommendations.append(f"Apply security patches for {cve_count} potential CVE vulnerabilities")
    
    # Web vulnerability recommendations
    web_vulns = False
    for key, value in results.items():
        if key.startswith('web_scan_port_'):
            if value.get('xss_vulnerabilities'):
                web_vulns = True
                recommendations.append("Implement input validation and output encoding to prevent XSS attacks")
            if value.get('sql_vulnerabilities'):
                web_vulns = True
                recommendations.append("Use parameterized queries or ORM to prevent SQL injection")
            
    if web_vulns:
        recommendations.append("Consider implementing a Web Application Firewall (WAF)")
    
    # If no specific recommendations, add general ones
    if not recommendations:
        recommendations = [
            "Keep all software and systems updated with latest security patches",
            "Implement network segmentation to limit attack surface",
            "Deploy a firewall with strict rule sets",
            "Implement regular security assessments"
        ]
    
    return recommendations

def print_report(results):
    """Print a comprehensive report with findings and recommendations"""
    print(f"\n{Fore.CYAN}=== Vulnerability Assessment Report ==={Style.RESET_ALL}")
    print("-" * 60)
    
    # Summary of severity
    severity = categorize_severity(results)
    print(f"\n{Fore.YELLOW}Severity Summary:{Style.RESET_ALL}")
    table = []
    for level, count in severity.items():
        color = Fore.GREEN
        if level == 'critical':
            color = Fore.RED + Style.BRIGHT
        elif level == 'high':
            color = Fore.RED
        elif level == 'medium':
            color = Fore.YELLOW
        
        table.append([f"{color}{level.capitalize()}{Style.RESET_ALL}", count])
    
    print(tabulate(table, headers=["Severity", "Count"]))
    
    # Calculate risk score (simple algorithm)
    risk_score = (
        severity['critical'] * 10 + 
        severity['high'] * 5 + 
        severity['medium'] * 2 + 
        severity['low'] * 0.5
    )
    
    risk_level = "Low"
    color = Fore.GREEN
    if risk_score > 30:
        risk_level = "Critical"
        color = Fore.RED + Style.BRIGHT
    elif risk_score > 15:
        risk_level = "High"
        color = Fore.RED
    elif risk_score > 5:
        risk_level = "Medium"
        color = Fore.YELLOW
    
    print(f"\n{Fore.YELLOW}Overall Risk Level: {color}{risk_level}{Style.RESET_ALL} (Score: {risk_score})")
    
    # Recommendations
    recommendations = generate_recommendations(results)
    print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")
    
    print(f"\n{Fore.GREEN}Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print("-" * 60)
