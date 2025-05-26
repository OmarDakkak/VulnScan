#!/bin/bash
# test_port_scan.sh - Test the basic port scanning functionality

echo "==== VulnScan Port Scanning Test ===="
echo "Testing basic port scan functionality..."

# Set up environment
export PYTHONPATH=src

# Test localhost scan (should be safe)
echo -e "\n[TEST 1] Scanning localhost (127.0.0.1)"
python3 -m vulnscan.cli scan 127.0.0.1 --ports 80,443,8080,22,21

# Test with verbose output
echo -e "\n[TEST 2] Scanning with verbose output"
python3 -m vulnscan.cli scan 127.0.0.1 --ports 80,443 --verbose

# Test with output file
echo -e "\n[TEST 3] Scanning with output to file"
python3 -m vulnscan.cli scan 127.0.0.1 --ports 80,443 --output test_results.json

# Verify the output file exists
if [ -f "test_results.json" ]; then
    echo "✓ Output file created successfully"
    # Display file content (first 10 lines)
    echo "File preview:"
    head -n 10 test_results.json
else
    echo "✗ Failed to create output file"
fi

echo -e "\nPort scanning tests completed."