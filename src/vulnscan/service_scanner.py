"""
service_scanner.py - Service fingerprinting and CVE vulnerability matching
"""
import re
import json
import socket
import requests
from datetime import datetime

class ServiceScanner:
    def __init__(self, target_ip, ports, timeout=5):
        self.target_ip = target_ip
        self.ports = ports
        self.timeout = timeout
        self.service_banners = {}
        self.vulnerabilities = []
        
        # Load CVE database cache if available
        self._load_cve_cache()
    
    def _load_cve_cache(self):
        """Load cached CVE data if available"""
        try:
            with open('cve_cache.json', 'r') as f:
                self.cve_cache = json.load(f)
                # Check if cache is older than 7 days
                cache_date = datetime.fromisoformat(self.cve_cache.get('last_updated', '2000-01-01'))
                now = datetime.now()
                if (now - cache_date).days > 7:
                    self.cve_cache = {'entries': {}, 'last_updated': now.isoformat()}
        except (FileNotFoundError, json.JSONDecodeError):
            self.cve_cache = {'entries': {}, 'last_updated': datetime.now().isoformat()}
    
    def _save_cve_cache(self):
        """Save CVE data to cache"""
        with open('cve_cache.json', 'w') as f:
            json.dump(self.cve_cache, f)
    
    def get_service_banner(self, port):
        """Connect to port and get service banner/info"""
        banner = None
        service = "unknown"
        version = None
        
        try:
            with socket.create_connection((self.target_ip, port), self.timeout) as s:
                # Send different probes depending on the port
                if port == 80 or port == 443 or port == 8080 or port == 8443:
                    s.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
                else:
                    s.send(b"\r\n\r\n")
                
                # Receive banner
                banner = s.recv(4096).decode('utf-8', errors='ignore')
                
                # Try to identify service and version
                if port == 80 or port == 443 or port == 8080 or port == 8443:
                    # HTTP server
                    server_match = re.search(r'Server: ([^\r\n]+)', banner)
                    if server_match:
                        service = "http"
                        version = server_match.group(1)
                elif port == 21:
                    # FTP
                    if "ftp" in banner.lower():
                        service = "ftp"
                        version_match = re.search(r'([0-9.]+)', banner)
                        if version_match:
                            version = version_match.group(1)
                elif port == 22:
                    # SSH
                    if "ssh" in banner.lower():
                        service = "ssh"
                        version_match = re.search(r'SSH-[0-9.]+-([^\s]+)', banner)
                        if version_match:
                            version = version_match.group(1)
                elif port == 25 or port == 587:
                    # SMTP
                    if "smtp" in banner.lower():
                        service = "smtp"
                        version_match = re.search(r'ESMTP ([^\s]+)', banner)
                        if version_match:
                            version = version_match.group(1)
                
        except Exception:
            return None, None, None
        
        return banner, service, version
    
    def scan_services(self):
        """Scan all ports and identify services"""
        results = {}
        
        for port in self.ports:
            banner, service, version = self.get_service_banner(port)
            
            if banner:
                results[port] = {
                    'service': service,
                    'version': version,
                    'banner': banner[:100] if banner else None  # Truncate long banners
                }
        
        self.service_banners = results
        return results
    
    def check_vulnerabilities(self):
        """Check identified services against known vulnerabilities"""
        vulnerabilities = []
        
        for port, info in self.service_banners.items():
            service = info.get('service', 'unknown')
            version = info.get('version')
            
            if not version:
                continue
                
            # Format the search query
            search_query = f"{service} {version}"
            
            # Check if we have this in cache
            if search_query in self.cve_cache['entries']:
                vuln_list = self.cve_cache['entries'][search_query]
            else:
                # Query NVD API (this is a simplified version, you might need an API key for production)
                try:
                    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_query}"
                    response = requests.get(nvd_url, timeout=10)
                    data = response.json()
                    
                    vuln_list = []
                    if 'vulnerabilities' in data:
                        for vuln in data['vulnerabilities']:
                            cve = vuln.get('cve', {})
                            cve_id = cve.get('id')
                            description = cve.get('descriptions', [])
                            description_text = next((d.get('value') for d in description if d.get('lang') == 'en'), "No description")
                            
                            # Get severity if available
                            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])
                            severity = "Unknown"
                            score = 0.0
                            if metrics:
                                severity = metrics[0].get('cvssData', {}).get('baseSeverity', "Unknown")
                                score = metrics[0].get('cvssData', {}).get('baseScore', 0.0)
                            
                            vuln_list.append({
                                'cve_id': cve_id,
                                'description': description_text,
                                'severity': severity,
                                'score': score
                            })
                    
                    # Cache the results
                    self.cve_cache['entries'][search_query] = vuln_list
                    self._save_cve_cache()
                    
                except Exception as e:
                    print(f"Error querying NVD API: {e}")
                    vuln_list = []
            
            # Add relevant vulnerabilities to the results
            for vuln in vuln_list:
                vuln_with_context = vuln.copy()
                vuln_with_context.update({
                    'port': port,
                    'service': service,
                    'version': version
                })
                vulnerabilities.append(vuln_with_context)
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def run_scan(self):
        """Run the full service scan"""
        results = {}
        
        # Scan for service information
        services = self.scan_services()
        results['services'] = services
        
        # Check for vulnerabilities in detected services
        vulns = self.check_vulnerabilities()
        results['vulnerabilities'] = vulns
        
        return results