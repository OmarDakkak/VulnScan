#!/bin/bash
# test_auto_scan.sh - Test the auto-scan functionality with different options

echo "==== VulnScan Auto-Scan Test ===="
echo "Testing auto-scan functionality..."

# Set up environment
export PYTHONPATH=src

# Test subnet scan (using a small local subnet)
echo -e "\n[TEST 1] Scanning small subnet (127.0.0.1/30)"
python3 -m vulnscan.cli auto-scan --subnet 127.0.0.1/30 --ports 80,443

# Test random IP scan with minimal count for testing
echo -e "\n[TEST 2] Random IP scan (2 addresses only)"
python3 -m vulnscan.cli auto-scan --random --count 2 --ports 80,443 --timeout 2

# Test with service scan option
echo -e "\n[TEST 3] Subnet scan with service fingerprinting"
python3 -m vulnscan.cli auto-scan --subnet 127.0.0.1/30 --service-scan --ports 80,443,22

# Test with database storage
echo -e "\n[TEST 4] Scan with database storage"
python3 -m vulnscan.cli auto-scan --subnet 127.0.0.1/30 --save-db

# Check if database was created
if [ -f "vulnscan.db" ]; then
    echo "✓ Database file created successfully"
else
    echo "✗ Database file was not created"
fi

echo -e "\nAuto-scan tests completed."