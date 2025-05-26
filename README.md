# VulnScan - Smart Ethical Vulnerability Scanner

VulnScan is an advanced command-line tool for ethical vulnerability assessment of IP-based websites and services. It's designed for security professionals and penetration testers to identify potential security vulnerabilities in systems they own or have explicit permission to test.

## ⚠️ Important: Ethical Usage Only

This tool is intended **ONLY** for ethical security assessments on systems you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations.

## Features

- **Port Scanning**: Detect open ports and running services
- **Web Vulnerability Scanning**: 
  - Cross-Site Scripting (XSS) detection
  - SQL Injection detection
  - Directory listing checks
  - Default credential testing
- **Service Fingerprinting**: Identify service versions and detect known vulnerabilities
- **CVE Database Integration**: Check services against known CVEs
- **Smart Reporting**: Risk assessment with severity ratings and recommendations
- **Database Storage**: Track vulnerabilities and scan history over time
- **Auto-Scanning**: Scan subnets or random public IPs for vulnerable systems

## Installation

### Requirements
- Python 3.8 or higher
- Required packages listed in `requirements.txt`

### Setup

1. Clone the repository or download the source code:

```bash
git clone https://github.com/OmarDakkak/VulnScan.git
cd VulnScan
```

2. Install the required packages:

```bash
pip install -r requirements.txt
```

3. Run the tool:

```bash
# From the project directory
PYTHONPATH=src python3 -m vulnscan.cli --help
```

## Usage

### Basic Scan

Scan a single IP address for vulnerabilities:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.1
```

### Smart Vulnerability Assessment

Perform an in-depth vulnerability assessment with service fingerprinting and web scanning:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.1 --smart-check --save-db
```

### Auto-Scan a Subnet

Scan an entire subnet for vulnerable systems:

```bash
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --subnet 192.168.1.0/24
```

### Scan Random Public IPs

Scan random public IP addresses (for research purposes only):

```bash
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --random --count 20
```

### Generate Reports

Generate vulnerability reports from the database:

```bash
# General report
PYTHONPATH=src python3 -m vulnscan.cli reports

# Report for specific IP
PYTHONPATH=src python3 -m vulnscan.cli reports --ip 192.168.1.1

# JSON format
PYTHONPATH=src python3 -m vulnscan.cli reports --format json --output report.json
```

## Command Options

### Scan Command

```
scan [OPTIONS] TARGET_IP

Options:
  -p, --ports TEXT         Comma-separated list of ports to scan
  -t, --threads INTEGER    Number of threads for scanning
  --timeout INTEGER        Connection timeout in seconds
  -o, --output PATH        Output file to save results
  --smart-check            Perform smart vulnerability assessment
  --service-scan           Identify service versions and check for CVEs
  --web-scan               Scan for web vulnerabilities
  --save-db                Save results to database for tracking
  -v, --verbose            Enable verbose output
```

### Auto-Scan Command

```
auto-scan [OPTIONS]

Options:
  --subnet TEXT           Subnet to scan in CIDR notation
  --random                Scan random public IP addresses
  --count INTEGER         Number of random IPs to scan
  -p, --ports TEXT        Comma-separated list of ports to scan
  -t, --threads INTEGER   Number of threads for scanning
  --timeout INTEGER       Connection timeout in seconds
  --smart-check           Perform smart vulnerability assessment
  --service-scan          Identify service versions and check for CVEs
  -o, --output PATH       Output file to save results
  --save-db               Save results to database for tracking
  -v, --verbose           Enable verbose output
```

## Project Structure

- `src/vulnscan/`: Main package directory
  - `cli.py`: Command-line interface
  - `scanner.py`: Basic port scanning functionality
  - `web_scanner.py`: Web vulnerability scanning
  - `service_scanner.py`: Service fingerprinting and CVE checking
  - `database.py`: Database integration for storing results
  - `utils.py`: Utility functions

## License

[MIT License](LICENSE)

## Disclaimer

The authors of this software are not responsible for any misuse or damage caused by this program. Use at your own risk and only on systems you own or have permission to test.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to [our GitHub repository](https://github.com/OmarDakkak/VulnScan).