#!/bin/bash
# run_all_tests.sh - Master script to run all test scripts in sequence

echo "=========================================="
echo "   VulnScan Test Suite - Running All Tests"
echo "=========================================="

# Set up environment
export PYTHONPATH=src

# Make all test scripts executable
chmod +x tests/test_*.sh

# Track test results
PASSED=0
FAILED=0
TOTAL=0

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
YELLOW='\033[1;33m'

run_test() {
    TOTAL=$((TOTAL + 1))
    TEST_NAME=$1
    
    echo -e "\n${YELLOW}Running Test Suite: $TEST_NAME${NC}"
    echo "----------------------------------------"
    
    if $TEST_NAME; then
        echo -e "${GREEN}✓ $TEST_NAME completed successfully${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ $TEST_NAME failed${NC}"
        FAILED=$((FAILED + 1))
    fi
    
    echo "----------------------------------------"
}

# Clean up any previous test artifacts
echo "Cleaning up previous test artifacts..."
rm -f test_results.json web_test_report.json service_test_results.json vulnscan.db cve_cache.json

# Run each test script
run_test ./tests/test_port_scan.sh
run_test ./tests/test_service_scan.sh
run_test ./tests/test_web_scan.sh
run_test ./tests/test_auto_scan.sh

# Print summary
echo -e "\n=========================================="
echo "           Test Summary"
echo "=========================================="
echo -e "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed successfully!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed. Please check the output above.${NC}"
    exit 1
fi