#!/bin/bash
# test_service_scan.sh - Test service fingerprinting and CVE detection capabilities

echo "==== VulnScan Service Fingerprinting Test ===="
echo "Testing service detection and CVE matching..."

# Set up environment
export PYTHONPATH=src

# Test service scan on localhost
echo -e "\n[TEST 1] Basic service scan on localhost"
python3 -m vulnscan.cli scan 127.0.0.1 --service-scan --ports 22,80,443

# Test against a public server (adjust as needed for ethical testing)
echo -e "\n[TEST 2] Service scan against test server"
python3 -m vulnscan.cli scan httpbin.org --service-scan --ports 80,443

# Test CVE cache functionality
echo -e "\n[TEST 3] Testing CVE cache creation"
python3 -m vulnscan.cli scan httpbin.org --service-scan --ports 80,443
# Check if cache was created
if [ -f "cve_cache.json" ]; then
    echo "✓ CVE cache file created successfully"
else
    echo "✗ CVE cache file was not created"
fi

# Test comprehensive scan with service and web vulnerability detection
echo -e "\n[TEST 4] Comprehensive service and web vulnerability scan"
python3 -m vulnscan.cli scan httpbin.org --smart-check --ports 80,443 --output service_test_results.json

echo -e "\nService scanning tests completed."