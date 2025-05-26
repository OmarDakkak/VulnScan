"""
scanner.py - Core vulnerability scanning logic for VulnScan
"""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from .utils import check_http, check_default_creds, check_directory_listing

class VulnerabilityScanner:
    def __init__(self, target_ip: str, ports: List[int], threads: int = 10, timeout: int = 5, verbose: bool = False):
        self.target_ip = target_ip
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose

    def run_scan(self) -> Dict[str, Any]:
        results = {}
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            port_results = list(executor.map(self.scan_port, self.ports))
        for port, res in zip(self.ports, port_results):
            results[port] = res
        return results

    def scan_port(self, port: int) -> Dict[str, Any]:
        result = {"open": False, "vulnerabilities": []}
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout):
                result["open"] = True
                # Run vulnerability checks
                vulns = []
                if port in [80, 443, 8080, 8443]:
                    if check_http(self.target_ip, port):
                        vulns.append("HTTP service detected")
                    if check_directory_listing(self.target_ip, port):
                        vulns.append("Directory listing enabled")
                    if check_default_creds(self.target_ip, port):
                        vulns.append("Default credentials accepted")
                result["vulnerabilities"] = vulns
        except Exception:
            pass
        return result

    def display_results(self, results: Dict[int, Any]):
        from tabulate import tabulate
        table = []
        for port, res in results.items():
            status = "Open" if res["open"] else "Closed"
            vulns = ", ".join(res["vulnerabilities"]) if res["vulnerabilities"] else "None"
            table.append([port, status, vulns])
        print(tabulate(table, headers=["Port", "Status", "Vulnerabilities"]))

    def save_results(self, results: Dict[int, Any], filename: str):
        import json
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
