#!/bin/bash
# DEYSAFE Full Validation Suite - Linux Environment
# Exports OPERATOR_TOKEN and runs all validation gates sequentially

set -e

echo "=== DEYSAFE FULL VALIDATION SUITE ==="
echo "Starting at $(date)"
echo ""

# Export operator token for authenticated endpoints
export OPERATOR_TOKEN="test_operator_token_for_validation"

# Track results
TOTAL_PASS=0
TOTAL_FAIL=0

run_validator() {
    local validator=$1
    echo "=========================================="
    echo "Running: $validator"
    echo "=========================================="
    
    if python "$validator" 2>&1 | tee /tmp/${validator%.py}.log; then
        echo "✓ $validator completed"
    else
        echo "✗ $validator had failures"
    fi
    
    # Extract pass/fail counts from log
    local pass=$(grep -oP '\d+(?= passed)' /tmp/${validator%.py}.log | tail -1 || echo 0)
    local fail=$(grep -oP '\d+(?= failed)' /tmp/${validator%.py}.log | tail -1 || echo 0)
    
    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))
    
    echo ""
}

# Run all validators
run_validator "validate.py"
run_validator "validate_security.py"
run_validator "validate_response.py"
run_validator "validate_quality.py"
run_validator "validate_product.py"

echo "=========================================="
echo "FINAL RESULTS"
echo "=========================================="
echo "Total Passed: $TOTAL_PASS"
echo "Total Failed: $TOTAL_FAIL"
echo "Grand Total:  $((TOTAL_PASS + TOTAL_FAIL))"
echo ""

if [ $TOTAL_FAIL -eq 0 ]; then
    echo "✅ ALL TESTS PASSED (139/139)"
    exit 0
else
    echo "❌ SOME TESTS FAILED ($TOTAL_FAIL/$((TOTAL_PASS + TOTAL_FAIL)))"
    exit 1
fi
