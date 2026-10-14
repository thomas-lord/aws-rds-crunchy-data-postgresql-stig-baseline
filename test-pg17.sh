#!/bin/bash
# PostgreSQL 17.8 STIG Profile Test Script
# Version: 3.2.0
# Date: 2026-10-13

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROFILE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUTS_FILE="${INPUTS_FILE:-inputs-pg17-test.yml}"
RESULTS_DIR="test-results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_FILE="$RESULTS_DIR/results-pg17-$TIMESTAMP.json"

# Functions
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check InSpec
    if ! command -v inspec &> /dev/null; then
        print_error "InSpec is not installed"
        echo "Install with: brew install inspec (macOS) or gem install inspec-bin"
        exit 1
    fi
    print_success "InSpec found: $(inspec --version | head -1)"
    
    # Check psql
    if ! command -v psql &> /dev/null; then
        print_error "psql client is not installed"
        echo "Install with: brew install postgresql (macOS)"
        exit 1
    fi
    print_success "psql found: $(psql --version)"
    
    # Check jq (optional but recommended)
    if ! command -v jq &> /dev/null; then
        print_warning "jq is not installed (optional, for JSON parsing)"
        echo "Install with: brew install jq (macOS)"
    else
        print_success "jq found: $(jq --version)"
    fi
    
    echo ""
}

# Check inputs file
check_inputs() {
    print_header "Checking Inputs File"
    
    if [ ! -f "$INPUTS_FILE" ]; then
        print_error "Inputs file not found: $INPUTS_FILE"
        echo ""
        echo "Create an inputs file with:"
        echo "  cp inputs-pg17-test.yml.example $INPUTS_FILE"
        echo "  # Edit with your database credentials"
        exit 1
    fi
    print_success "Inputs file found: $INPUTS_FILE"
    
    # Extract connection details
    PG_HOST=$(grep "pg_host:" "$INPUTS_FILE" | head -1 | sed "s/.*['\"]\\(.*\\)['\"]/\\1/")
    PG_USER=$(grep "pg_dba:" "$INPUTS_FILE" | head -1 | sed "s/.*['\"]\\(.*\\)['\"]/\\1/")
    
    print_info "Database: $PG_HOST"
    print_info "User: $PG_USER"
    echo ""
}

# Validate profile
validate_profile() {
    print_header "Step 1: Validating Profile Structure"
    
    cd "$PROFILE_DIR"
    
    if inspec check . > /dev/null 2>&1; then
        print_success "Profile validation passed"
    else
        print_error "Profile validation failed"
        inspec check .
        exit 1
    fi
    echo ""
}

# Test database connectivity
test_connectivity() {
    print_header "Step 2: Testing Database Connectivity"
    
    PG_HOST=$(grep "pg_host:" "$INPUTS_FILE" | head -1 | sed "s/.*['\"]\\(.*\\)['\"]/\\1/")
    PG_USER=$(grep "pg_dba:" "$INPUTS_FILE" | head -1 | sed "s/.*['\"]\\(.*\\)['\"]/\\1/")
    PG_PASS=$(grep "pg_dba_password:" "$INPUTS_FILE" | head -1 | sed "s/.*['\"]\\(.*\\)['\"]/\\1/")
    
    export PGPASSWORD="$PG_PASS"
    
    if psql -h "$PG_HOST" -U "$PG_USER" -d postgres -c "SELECT version();" > /dev/null 2>&1; then
        print_success "Database connection successful"
        
        # Get PostgreSQL version
        PG_VERSION=$(psql -h "$PG_HOST" -U "$PG_USER" -d postgres -t -c "SHOW server_version;" | xargs)
        print_info "PostgreSQL version: $PG_VERSION"
        
        # Check if it's version 17
        if [[ $PG_VERSION == 17* ]]; then
            print_success "Confirmed PostgreSQL 17.x"
        else
            print_warning "Not PostgreSQL 17.x - results may differ"
        fi
    else
        print_error "Database connection failed"
        echo "Check your credentials and network connectivity"
        exit 1
    fi
    
    unset PGPASSWORD
    echo ""
}

# Run single control test
test_single_control() {
    print_header "Step 3: Running Single Control Test (V-233596)"
    
    if inspec exec . \
        --input-file="$INPUTS_FILE" \
        --controls=V-233596 \
        --reporter=cli 2>&1 | grep -q "0 failed"; then
        print_success "Single control test passed"
    else
        print_warning "Single control test had issues (may be expected)"
    fi
    echo ""
}

# Run full profile
run_full_profile() {
    print_header "Step 4: Running Full Profile"
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    print_info "This may take several minutes..."
    
    if inspec exec . \
        --input-file="$INPUTS_FILE" \
        --reporter=cli "json:$RESULTS_FILE" \
        --show-progress; then
        print_success "Full profile execution completed"
    else
        print_warning "Profile execution completed with some failures"
    fi
    
    print_info "Results saved to: $RESULTS_FILE"
    echo ""
}

# Generate summary
generate_summary() {
    print_header "Step 5: Test Summary"
    
    if command -v jq &> /dev/null && [ -f "$RESULTS_FILE" ]; then
        echo ""
        echo "Overall Summary:"
        jq -r '.profiles[0].summary | 
            "  Total Controls: \(.controls.total)\n" +
            "  Passed: \(.controls.passed.total) (\(.controls.passed.total * 100 / .controls.total | floor)%)\n" +
            "  Failed: \(.controls.failed.total) (\(.controls.failed.total * 100 / .controls.total | floor)%)\n" +
            "  Skipped: \(.controls.skipped.total) (\(.controls.skipped.total * 100 / .controls.total | floor)%)\n" +
            "  Not Reviewed: \(.controls.not_reviewed.total)\n" +
            "  Not Applicable: \(.controls.not_applicable.total)"' "$RESULTS_FILE"
        
        echo ""
        echo "Failed Controls:"
        FAILED_COUNT=$(jq -r '.profiles[0].controls[] | select(.results[0].status == "failed") | .id' "$RESULTS_FILE" | wc -l | xargs)
        
        if [ "$FAILED_COUNT" -eq 0 ]; then
            print_success "No failed controls!"
        else
            jq -r '.profiles[0].controls[] | 
                select(.results[0].status == "failed") | 
                "  - \(.id): \(.title)"' "$RESULTS_FILE" | head -10
            
            if [ "$FAILED_COUNT" -gt 10 ]; then
                echo "  ... and $(($FAILED_COUNT - 10)) more"
            fi
        fi
        
        echo ""
        echo "Key Controls to Review:"
        echo "  - V-233596 (Password Encryption):"
        jq -r '.profiles[0].controls[] | 
            select(.id == "V-233596") | 
            "    Status: \(.results[0].status)"' "$RESULTS_FILE"
        
        echo "  - V-233569 (Log Connections):"
        jq -r '.profiles[0].controls[] | 
            select(.id == "V-233569") | 
            "    Status: \(.results[0].status)"' "$RESULTS_FILE"
        
        echo "  - V-233598 (pgaudit):"
        jq -r '.profiles[0].controls[] | 
            select(.id == "V-233598") | 
            "    Status: \(.results[0].status)"' "$RESULTS_FILE"
    else
        print_warning "jq not available or results file not found - skipping detailed summary"
        print_info "View results manually: cat $RESULTS_FILE"
    fi
    echo ""
}

# Print next steps
print_next_steps() {
    print_header "Next Steps"
    
    echo "1. Review results:"
    echo "   cat $RESULTS_FILE | jq '.profiles[0].summary'"
    echo ""
    echo "2. View in Heimdall Lite:"
    echo "   https://heimdall-lite.mitre.org/"
    echo "   Upload: $RESULTS_FILE"
    echo ""
    echo "3. Generate report:"
    echo "   See TESTING_GUIDE.md for report generation"
    echo ""
    echo "4. Address findings:"
    echo "   - Review failed controls"
    echo "   - Update RDS configuration"
    echo "   - Document exceptions"
    echo ""
    
    print_success "Testing complete!"
}

# Main execution
main() {
    clear
    print_header "PostgreSQL 17.8 STIG Profile Test"
    echo "Profile Version: 3.2.0"
    echo "Date: $(date)"
    echo ""
    
    check_prerequisites
    check_inputs
    validate_profile
    test_connectivity
    test_single_control
    run_full_profile
    generate_summary
    print_next_steps
}

# Run main function
main "$@"
