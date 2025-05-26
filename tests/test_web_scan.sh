#!/bin/bash
# test_web_scan.sh - Test the web vulnerability scanning functionality

echo "==== VulnScan Web Vulnerability Scanner Test ===="
echo "Testing web scanning capabilities..."

# Set up environment
export PYTHONPATH=src

# Create a temporary test target (publicly available site for ethical testing)
TEST_TARGET="httpbin.org"

# Test basic scan with web vulnerability check
echo -e "\n[TEST 1] Basic web scan against test target"
python3 -m vulnscan.cli scan $TEST_TARGET --web-scan --ports 80,443

# Test with smart check (comprehensive scan)
echo -e "\n[TEST 2] Smart check with web vulnerability assessment"
python3 -m vulnscan.cli scan $TEST_TARGET --smart-check --ports 80,443 --timeout 10

# Test report generation
echo -e "\n[TEST 3] Generate report after scan"
python3 -m vulnscan.cli scan $TEST_TARGET --smart-check --save-db --ports 80,443
python3 -m vulnscan.cli reports --ip $TEST_TARGET

# Test JSON report format
echo -e "\n[TEST 4] Generate JSON format report"
python3 -m vulnscan.cli reports --ip $TEST_TARGET --format json --output web_test_report.json

# Check if report was created
if [ -f "web_test_report.json" ]; then
    echo "✓ JSON report created successfully"
    # Display file content preview
    echo "Report preview:"
    head -n 15 web_test_report.json
else
    echo "✗ JSON report was not created"
fi

echo -e "\nWeb scanning tests completed."