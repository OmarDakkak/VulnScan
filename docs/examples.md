# VulnScan Usage Examples

This document provides practical examples of how to use VulnScan in various security testing scenarios.

## Basic Usage Scenarios

### Example 1: Quick Check of a Web Server

A basic scan to check if a web server has common vulnerabilities:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.10 --ports 80,443
```

This performs a quick check of ports 80 and 443 for common web vulnerabilities like directory listing.

### Example 2: Comprehensive Web Application Assessment

A complete security assessment of a web application:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.10 --smart-check --web-scan --save-db --output webapp_scan.json
```

This performs:
- Port scanning
- Service fingerprinting
- CVE matching
- Web vulnerability scanning (XSS, SQLi)
- Stores results in database
- Saves JSON output to file

### Example 3: Scanning Multiple IP Addresses

Scan an entire subnet for vulnerable systems:

```bash
# Create a file with IPs
echo "192.168.1.1" > targets.txt
echo "192.168.1.10" >> targets.txt
echo "192.168.1.20" >> targets.txt

# Run batch scan
PYTHONPATH=src python3 -m vulnscan.cli batch targets.txt --ports 22,80,443 --output batch_results.json
```

### Example 4: Finding Vulnerable Systems on a Network

Automatically scan a subnet to find potentially vulnerable systems:

```bash
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --subnet 192.168.1.0/24 --service-scan
```

This will check the entire subnet and identify systems with potential vulnerabilities.

## Advanced Usage Scenarios

### Example 5: Generating Security Reports

After conducting multiple scans and saving to the database, generate comprehensive reports:

```bash
# Generate summary report
PYTHONPATH=src python3 -m vulnscan.cli reports

# Generate report for specific IP
PYTHONPATH=src python3 -m vulnscan.cli reports --ip 192.168.1.10 --format json --output security_report.json
```

### Example 6: Continuous Monitoring

Set up recurring scans to monitor for new vulnerabilities:

```bash
#!/bin/bash
# weekly_scan.sh

DATE=$(date +%Y-%m-%d)
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --subnet 192.168.1.0/24 --smart-check --save-db
PYTHONPATH=src python3 -m vulnscan.cli reports --format json --output "report_${DATE}.json"
```

Add this script to your crontab to run weekly:
```
0 2 * * 0 /path/to/weekly_scan.sh
```

### Example 7: Service Version Vulnerability Analysis

Focus on detecting outdated software versions with known vulnerabilities:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.10 --service-scan --ports 20-30,80-443 --output version_scan.json
```

This will scan common service ports and check if any services match known vulnerable versions.

## Specialized Scenarios

### Example 8: Custom Port Range for Obscure Services

Some services may run on non-standard ports:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.10 --ports 1-1024,8000-9000 --timeout 10
```

This scans both well-known ports (1-1024) and a common range for alternative web services.

### Example 9: Focused Web Vulnerability Testing

When you only want to check for web vulnerabilities:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.10 --web-scan --ports 80,443,8080,8443
```

### Example 10: Random IP Scanning for Research

For security research purposes (ensure you have proper legal authorization):

```bash
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --random --count 50 --ports 80 --output research_data.json
```

This will scan 50 random public IP addresses and save the results.

## Integration Examples

### Example 11: Using VulnScan with Other Tools

Combining VulnScan with other security tools:

```bash
#!/bin/bash
# Run nmap for initial discovery
nmap -sP 192.168.1.0/24 -oG nmap_sweep.txt

# Extract live hosts
grep "Up" nmap_sweep.txt | cut -d " " -f 2 > live_hosts.txt

# Scan those hosts with VulnScan
PYTHONPATH=src python3 -m vulnscan.cli batch live_hosts.txt --smart-check --save-db
```

### Example 12: Automating VulnScan with Python

You can also integrate VulnScan into your Python scripts:

```python
import subprocess
import json

# Run VulnScan
subprocess.run([
    "python3", "-m", "vulnscan.cli", "scan", 
    "192.168.1.10", "--output", "results.json"
], env={"PYTHONPATH": "src"})

# Process results
with open("results.json", "r") as f:
    results = json.load(f)

# Analyze results in your script
open_ports = []
for port, info in results["port_scan"].items():
    if info.get("open"):
        open_ports.append(port)

print(f"Open ports: {', '.join(open_ports)}")
```

## Best Practices

1. **Start small**: Begin with focused scans before expanding scope
2. **Monitor system impact**: Watch for any adverse effects on target systems
3. **Verify findings**: Manually check vulnerabilities to confirm they're not false positives
4. **Document everything**: Keep records of all scan parameters and results
5. **Respect privacy**: Don't extract sensitive data during testing

These examples demonstrate the flexibility of VulnScan for different security testing needs. Remember to always use this tool ethically and only on systems you have permission to test.