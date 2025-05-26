# VulnScan API Reference

This document provides technical details about VulnScan's internal modules and classes for developers who want to extend or integrate with the tool.

## Module Structure

VulnScan is organized into several Python modules:

- `cli.py`: Command-line interface
- `scanner.py`: Basic port scanning engine
- `web_scanner.py`: Web vulnerability scanning
- `service_scanner.py`: Service fingerprinting and CVE detection
- `database.py`: Database storage and reporting
- `utils.py`: Utility functions

## Core Classes

### `VulnerabilityScanner`

The base scanner class that handles port scanning and basic vulnerability detection.

```python
# From scanner.py
class VulnerabilityScanner:
    def __init__(self, target_ip: str, ports: List[int], threads: int = 10, 
                 timeout: int = 5, verbose: bool = False):
        # Initialize scanner with target IP and scanning parameters
        
    def run_scan(self) -> Dict[str, Any]:
        # Run the port scan and return results
        
    def scan_port(self, port: int) -> Dict[str, Any]:
        # Scan individual port
        
    def display_results(self, results: Dict[int, Any]):
        # Display scan results in table format
        
    def save_results(self, results: Dict[int, Any], filename: str):
        # Save results to a file
```

### `WebScanner`

Specialized scanner for web vulnerability detection.

```python
# From web_scanner.py
class WebScanner:
    def __init__(self, target, threads=5, timeout=10, user_agent=None, cookies=None):
        # Initialize web scanner
        
    def crawl(self, max_urls=100):
        # Crawl website to discover URLs and forms
        
    def scan_xss(self):
        # Scan for XSS vulnerabilities
        
    def scan_sqli(self):
        # Scan for SQL injection vulnerabilities
        
    def run_scan(self):
        # Run all web vulnerability scans
```

### `ServiceScanner`

Identifies service versions and checks for known CVEs.

```python
# From service_scanner.py
class ServiceScanner:
    def __init__(self, target_ip, ports, timeout=5):
        # Initialize service scanner
        
    def get_service_banner(self, port):
        # Get service banner/info from port
        
    def scan_services(self):
        # Scan all ports and identify services
        
    def check_vulnerabilities(self):
        # Check services against known vulnerabilities
        
    def run_scan(self):
        # Run the full service scan
```

### `VulnDatabase`

Handles database operations for storing and retrieving scan results.

```python
# From database.py
class VulnDatabase:
    def __init__(self, db_path='vulnscan.db'):
        # Initialize database connection
        
    def add_target(self, ip_address, hostname=None, tags=None):
        # Add a new target to the database
        
    def add_scan_result(self, target_id, scan_type, results):
        # Add scan results to the database
        
    def get_target_history(self, ip_address):
        # Get scan history for a target
        
    def get_recent_scans(self, limit=10):
        # Get recent scan summaries
        
    def get_vulnerability_stats(self):
        # Get vulnerability statistics
```

## Integration Examples

### Extending with a Custom Scanner

```python
from vulnscan.scanner import VulnerabilityScanner

class CustomScanner(VulnerabilityScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.custom_config = kwargs.get('custom_config', {})
    
    def run_custom_scan(self):
        # Custom scanning logic here
        results = super().run_scan()
        
        # Add custom scanning functionality
        for port, info in results.items():
            if info.get('open'):
                # Custom port checks
                pass
                
        return results

# Usage
scanner = CustomScanner(target_ip='192.168.1.1', ports=[80, 443])
results = scanner.run_custom_scan()
```

### Using the Database API

```python
from vulnscan.database import VulnDatabase

# Initialize database
db = VulnDatabase()

# Add a target
target_id = db.add_target('192.168.1.1', tags=['web-server'])

# Add scan results
scan_results = {
    '80': {'open': True, 'vulnerabilities': ['Directory listing enabled']},
    '443': {'open': True, 'vulnerabilities': []}
}
db.add_scan_result(target_id, 'port', scan_results)

# Get target history
history = db.get_target_history('192.168.1.1')
print(f"Found {len(history['vulnerabilities'])} vulnerabilities")

# Get vulnerability statistics
stats = db.get_vulnerability_stats()
print(f"Critical vulnerabilities: {stats['by_severity'].get('critical', 0)}")
```

### Adding a New Vulnerability Check

```python
from vulnscan.web_scanner import WebScanner

class EnhancedWebScanner(WebScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def scan_csrf(self):
        """Scan for CSRF vulnerabilities"""
        results = []
        
        for form in self.forms:
            # Check for CSRF tokens
            has_csrf_token = any(
                input_field.get('name', '').lower() in ('csrf', 'token', 'csrf_token', 'xsrf') 
                for input_field in form['inputs']
            )
            
            if not has_csrf_token:
                results.append({
                    'type': 'CSRF',
                    'url': form['action'],
                    'method': form['method'],
                    'evidence': "Form without CSRF protection"
                })
        
        return results
    
    def run_scan(self):
        results = super().run_scan()
        results['csrf_vulnerabilities'] = self.scan_csrf()
        return results
```

## CLI Integration

To add a new command to the CLI:

```python
# In cli.py
@cli.command()
@click.argument('target_ip')
@click.option('--custom-option', help='Description of the custom option')
def custom_command(target_ip, custom_option):
    """Description of the custom command"""
    click.echo(f"Running custom command on {target_ip}")
    
    # Your command implementation here
```

## Best Practices

1. **Error Handling**: Always catch exceptions and provide meaningful error messages.
2. **Timeouts**: Use appropriate timeouts for network operations.
3. **Resource Management**: Close connections and files properly.
4. **Documentation**: Document your functions and classes properly.
5. **Ethical Use**: Ensure your extensions follow ethical guidelines.