# VulnScan User Guide

## Introduction

VulnScan is a command-line tool designed for ethical vulnerability assessment of IP-based websites and services. This guide will walk you through the various features of VulnScan and how to use them effectively.

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Scanning Modes](#scanning-modes)
4. [Advanced Features](#advanced-features)
5. [Interpreting Results](#interpreting-results)
6. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/vulnscan.git
   cd vulnscan
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Verify installation:
   ```
   PYTHONPATH=src python3 -m vulnscan.cli --version
   ```

## Basic Usage

### Single IP Scanning

To scan a single IP address:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.1
```

This will perform a basic scan of common ports (80, 443, 8080, 8443) on the target IP.

### Command Line Options

- `-p, --ports`: Specify ports to scan (comma-separated)
- `-t, --threads`: Number of threads for parallel scanning
- `--timeout`: Connection timeout in seconds
- `-o, --output`: Save results to a file
- `-v, --verbose`: Enable verbose output

Example with options:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan 192.168.1.1 -p 80,443,22,21 -t 15 --timeout 10 -o results.json -v
```

## Scanning Modes

### 1. Port Scanning

Basic port scanning detects open ports and identifies common web vulnerabilities:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan TARGET_IP
```

### 2. Service Fingerprinting

Detect service versions and match against known CVEs:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan TARGET_IP --service-scan
```

### 3. Web Vulnerability Scanning

Scan for web vulnerabilities like XSS and SQL Injection:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan TARGET_IP --web-scan
```

### 4. Auto-Scanning

Scan entire subnets or random IP addresses:

```bash
# Scan subnet
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --subnet 192.168.1.0/24

# Scan random IPs
PYTHONPATH=src python3 -m vulnscan.cli auto-scan --random --count 10
```

### 5. Smart Scanning

Perform comprehensive vulnerability assessment:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan TARGET_IP --smart-check
```

## Advanced Features

### Database Integration

VulnScan can store scan results to a SQLite database for tracking vulnerabilities over time:

```bash
PYTHONPATH=src python3 -m vulnscan.cli scan TARGET_IP --save-db
```

### Reporting

Generate vulnerability reports from the database:

```bash
# General report
PYTHONPATH=src python3 -m vulnscan.cli reports

# Report for specific IP
PYTHONPATH=src python3 -m vulnscan.cli reports --ip TARGET_IP

# JSON format
PYTHONPATH=src python3 -m vulnscan.cli reports --format json --output report.json
```

## Interpreting Results

VulnScan categorizes vulnerabilities by severity:
- **Critical**: Requires immediate attention (e.g., SQL Injection)
- **High**: Serious vulnerabilities that should be addressed soon
- **Medium**: Important but less urgent issues
- **Low**: Minor concerns
- **Info**: Informational findings

Each scan provides:
1. List of open ports
2. Service information (if available)
3. Detected vulnerabilities
4. Risk assessment
5. Recommended actions

## Troubleshooting

### Common Issues

1. **Connection timeouts**:
   - Increase timeout with `--timeout` option
   - Check firewall settings

2. **False positives**:
   - Use `--verbose` to get more information
   - Manually verify findings

3. **Database errors**:
   - Check file permissions
   - Ensure SQLite is available on your system

### Getting Help

Run any command with `--help` for usage information:

```bash
PYTHONPATH=src python3 -m vulnscan.cli --help
PYTHONPATH=src python3 -m vulnscan.cli scan --help
```