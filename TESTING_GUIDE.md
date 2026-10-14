# Testing Guide - PostgreSQL 17.8 STIG Profile

## Overview

This guide provides step-by-step instructions for testing the updated AWS RDS Crunchy Data PostgreSQL STIG baseline profile (v3.2.0) against PostgreSQL 17.8.

---

## Prerequisites

### 1. InSpec Installation

```bash
# Check if InSpec is installed
inspec --version

# If not installed, install InSpec (choose one method):

# Method 1: Using Homebrew (macOS)
brew install inspec

# Method 2: Using gem
gem install inspec-bin

# Method 3: Download from Chef
# Visit: https://downloads.chef.io/tools/inspec
```

### 2. PostgreSQL Client (psql)

```bash
# Check if psql is installed
which psql
psql --version

# If not installed:

# macOS
brew install postgresql

# Linux (RHEL/CentOS)
sudo yum install postgresql

# Linux (Ubuntu/Debian)
sudo apt-get install postgresql-client
```

### 3. AWS RDS PostgreSQL 17.8 Instance

You need access to an AWS RDS PostgreSQL 17.8 instance with:
- Master username and password
- Network access from your testing machine
- Security group allowing port 5432 from your IP
- pgaudit extension installed (recommended)

---

## Test Environment Setup

### Option 1: Test Against Existing RDS Instance

If you already have a PostgreSQL 17.8 RDS instance:

```bash
# Test connectivity
psql -h your-instance.region.rds.amazonaws.com \
     -U postgres \
     -d postgres \
     -c "SELECT version();"
```

### Option 2: Create New Test RDS Instance

```bash
# Using AWS CLI
aws rds create-db-instance \
    --db-instance-identifier pg17-stig-test \
    --db-instance-class db.t3.micro \
    --engine postgres \
    --engine-version 17.8 \
    --master-username postgres \
    --master-user-password 'YourSecurePassword123!' \
    --allocated-storage 20 \
    --vpc-security-group-ids sg-xxxxxxxx \
    --db-subnet-group-name your-subnet-group \
    --backup-retention-period 7 \
    --publicly-accessible

# Wait for instance to be available (5-10 minutes)
aws rds wait db-instance-available \
    --db-instance-identifier pg17-stig-test

# Get the endpoint
aws rds describe-db-instances \
    --db-instance-identifier pg17-stig-test \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text
```

### Option 3: Use Docker for Local Testing (PostgreSQL 17, not RDS)

```bash
# Note: This won't test RDS-specific features but good for basic validation
docker run -d \
    --name postgres17-test \
    -e POSTGRES_PASSWORD=testpassword \
    -p 5432:5432 \
    postgres:17

# Test connection
psql -h localhost -U postgres -c "SELECT version();"
```

---

## Configuration

### 1. Create Inputs File

Create a file named `inputs-pg17-test.yml`:

```yaml
# Connection Settings
pg_dba: 'postgres'
pg_dba_password: 'YourSecurePassword123!'
pg_host: 'your-instance.region.rds.amazonaws.com'
pg_db: 'postgres'
pg_port: 5432

# Version Information
pg_version: '17.8'

# Windows or Linux Runner (default: false for Linux/macOS)
windows_runner: false

# User Accounts
pg_users:
  - "postgres"
  - "rds_iam"
  - "rds_pgaudit"
  - "rds_replication"
  - "rds_superuser"
  - "rdsadmin"
  - "rdsrepladmin"

# Superuser Accounts
pg_superusers:
  - "rdsadmin"

# RDS Superusers
rds_superusers:
  - "postgres"

# System Resource Users (for V-233520, V-233523)
pg_system_resource_users:
  - "postgres"
  - "rds_superuser"

# System Settings
pg_owner: "postgres"
pg_group: "postgres"

# Extensions
approved_ext:
  - "pgaudit"

# Approved Packages (usually empty for RDS)
approved_packages: []

# PostgreSQL Settings
pg_max_connections: 100
pg_timezone: 'UTC'
pg_ssl: 'on'

# Audit Settings
pgaudit_log_items:
  - 'ddl'
  - 'role'
  - 'read'
  - 'write'

pgaudit_log_line_items:
  - '%m'
  - '%u'
  - '%c'
  - '%d'
  - '%p'
  - '%r'

# Replicas (if applicable)
pg_replicas: []

# Object Privileges (for V-233546)
pg_object_granted_privileges: 'arwdDxt'
pg_object_public_privileges: 'r'
pg_object_exceptions: []
```

### 2. Secure Your Credentials

**Option A: Use Environment Variables**

```bash
# Set password as environment variable
export PG_DBA_PASSWORD='YourSecurePassword123!'

# Modify inputs file to use environment variable
# In inputs-pg17-test.yml, change:
# pg_dba_password: <%= ENV['PG_DBA_PASSWORD'] %>
```

**Option B: Use AWS Secrets Manager**

```bash
# Store password in Secrets Manager
aws secretsmanager create-secret \
    --name pg17-test-password \
    --secret-string 'YourSecurePassword123!'

# Retrieve in script
export PG_DBA_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id pg17-test-password \
    --query SecretString \
    --output text)
```

---

## Running Tests

### 1. Validate Profile Structure

```bash
cd /Users/thomaslord/Work/Coding/git/BAH/TaMIS/aws-rds-crunchy-data-postgresql-stig-baseline

# Check profile syntax and structure
inspec check .
```

Expected output:
```
Location:    /path/to/aws-rds-crunchy-data-postgresql-stig-baseline
Profile:     aws-rds-crunchy-data-postgresql-stig-baseline
Controls:    [number]
Timestamp:   [timestamp]
Valid:       true
```

### 2. Test Database Connectivity

```bash
# Test psql connection first
psql -h your-instance.region.rds.amazonaws.com \
     -U postgres \
     -d postgres \
     -c "SELECT version();"

# Verify PostgreSQL version
psql -h your-instance.region.rds.amazonaws.com \
     -U postgres \
     -d postgres \
     -c "SHOW server_version;"
```

### 3. Run Basic Test (Single Control)

Test one control first to verify connectivity:

```bash
# Run just one control to test
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --controls=V-233596 \
    --reporter=cli

# This tests password encryption - should show scram-sha-256 for PG 17
```

### 4. Run Full Profile

```bash
# Run all controls with CLI output
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --reporter=cli

# Run with JSON output for analysis
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --reporter=json:results-pg17.json

# Run with both CLI and JSON
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --reporter=cli json:results-pg17.json
```

### 5. Run with Verbose Output (for debugging)

```bash
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --reporter=cli \
    --log-level=debug
```

---

## Analyzing Results

### 1. View Results in Terminal

The CLI reporter shows:
- ✓ Passed controls (green)
- ✗ Failed controls (red)
- ↺ Skipped controls (yellow)

### 2. Analyze JSON Results

```bash
# View summary
cat results-pg17.json | jq '.profiles[0].summary'

# Count passed/failed/skipped
cat results-pg17.json | jq '.profiles[0].controls[] | .results[0].status' | sort | uniq -c

# List failed controls
cat results-pg17.json | jq '.profiles[0].controls[] | select(.results[0].status == "failed") | .id'

# View specific control
cat results-pg17.json | jq '.profiles[0].controls[] | select(.id == "V-233596")'
```

### 3. View in Heimdall (Recommended)

```bash
# Option 1: Use Heimdall Lite (no installation)
# 1. Go to https://heimdall-lite.mitre.org/
# 2. Click "Load JSON"
# 3. Upload results-pg17.json
# 4. View interactive results

# Option 2: Install Heimdall Server (for team use)
# See: https://github.com/mitre/heimdall
```

---

## Comparison Testing

### Compare PostgreSQL 17 vs Previous Version

```bash
# Run against PostgreSQL 15 (if available)
inspec exec . \
    --input-file=inputs-pg15.yml \
    --reporter=json:results-pg15.json

# Run against PostgreSQL 17
inspec exec . \
    --input-file=inputs-pg17.yml \
    --reporter=json:results-pg17.json

# Compare results
diff <(cat results-pg15.json | jq '.profiles[0].controls[].id' | sort) \
     <(cat results-pg17.json | jq '.profiles[0].controls[].id' | sort)

# Compare pass/fail status
diff <(cat results-pg15.json | jq '.profiles[0].controls[] | "\(.id): \(.results[0].status)"' | sort) \
     <(cat results-pg17.json | jq '.profiles[0].controls[] | "\(.id): \(.results[0].status)"' | sort)
```

---

## Expected Results for PostgreSQL 17.8

### Key Controls to Verify

#### V-233596: Password Encryption
```bash
# Should show: scram-sha-256
psql -h your-instance -U postgres -d postgres -c "SHOW password_encryption;"
```
**Expected:** ✓ PASS (scram-sha-256)

#### V-233569: Log Connections/Disconnections
```bash
psql -h your-instance -U postgres -d postgres -c "SHOW log_connections;"
psql -h your-instance -U postgres -d postgres -c "SHOW log_disconnections;"
```
**Expected:** ✓ PASS (both should be 'on')

#### V-233598: pgaudit Extension
```bash
psql -h your-instance -U postgres -d postgres -c "SHOW shared_preload_libraries;"
```
**Expected:** ✓ PASS (should include 'pgaudit')

### Controls Expected to Skip

These controls are skipped because AWS manages the OS:
- V-233513, V-233515, V-233517, V-233518, V-233519
- V-233540, V-233541, V-233550
- V-233577, V-233583, V-233585
- V-233593, V-233594
- V-233602, V-233609
- V-233617, V-233618, V-233619, V-233623

These controls require manual review:
- V-233512, V-233514 (RDS audit log system)
- V-233521, V-233525, V-233526, V-233527, V-233528
- V-233529, V-233531, V-233533
- And many others (see profile for complete list)

---

## Troubleshooting

### Issue: Connection Refused

```bash
# Check security group
aws ec2 describe-security-groups --group-ids sg-xxxxxxxx

# Verify your IP is allowed
curl -s https://checkip.amazonaws.com

# Test with telnet
telnet your-instance.region.rds.amazonaws.com 5432
```

### Issue: Authentication Failed

```bash
# Verify credentials
psql -h your-instance -U postgres -d postgres

# Check RDS parameter group
aws rds describe-db-parameters \
    --db-parameter-group-name your-parameter-group \
    --query 'Parameters[?ParameterName==`password_encryption`]'
```

### Issue: InSpec Errors

```bash
# Clear InSpec cache
rm -rf ~/.inspec/cache

# Re-run with debug logging
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --reporter=cli \
    --log-level=debug 2>&1 | tee debug.log
```

### Issue: Control Failures

```bash
# Run specific failing control
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --controls=V-233XXX \
    --reporter=cli

# Check PostgreSQL settings
psql -h your-instance -U postgres -d postgres -c "SHOW ALL;" > pg_settings.txt
```

---

## Test Checklist

### Pre-Test
- [ ] InSpec installed and working
- [ ] psql client installed
- [ ] RDS PostgreSQL 17.8 instance available
- [ ] Network connectivity verified
- [ ] Credentials configured
- [ ] Input file created and validated

### Basic Tests
- [ ] `inspec check .` passes
- [ ] psql connection successful
- [ ] PostgreSQL version confirmed as 17.x
- [ ] Single control test passes

### Full Test Run
- [ ] Full profile execution completes
- [ ] JSON results generated
- [ ] Results viewable in Heimdall
- [ ] Pass/fail counts documented

### Validation
- [ ] Password encryption shows scram-sha-256
- [ ] Expected controls pass
- [ ] Expected controls skip (AWS-managed)
- [ ] No unexpected failures
- [ ] Results match expectations

### Comparison (if applicable)
- [ ] Compared with PostgreSQL 15 results
- [ ] Differences documented
- [ ] New failures investigated
- [ ] Changes justified

### Documentation
- [ ] Test results saved
- [ ] Issues documented
- [ ] Exceptions noted
- [ ] Report generated

---

## Automated Testing Script

Create a script `test-pg17.sh`:

```bash
#!/bin/bash
set -e

echo "=== PostgreSQL 17.8 STIG Profile Test ==="
echo ""

# Configuration
PROFILE_DIR="/Users/thomaslord/Work/Coding/git/BAH/TaMIS/aws-rds-crunchy-data-postgresql-stig-baseline"
INPUTS_FILE="inputs-pg17-test.yml"
RESULTS_DIR="test-results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

cd "$PROFILE_DIR"

# Create results directory
mkdir -p "$RESULTS_DIR"

echo "Step 1: Validating profile structure..."
inspec check . || { echo "Profile validation failed!"; exit 1; }
echo "✓ Profile validation passed"
echo ""

echo "Step 2: Testing database connectivity..."
psql -h $(grep pg_host "$INPUTS_FILE" | cut -d"'" -f2) \
     -U $(grep pg_dba: "$INPUTS_FILE" | head -1 | cut -d"'" -f2) \
     -d postgres \
     -c "SELECT version();" || { echo "Database connection failed!"; exit 1; }
echo "✓ Database connection successful"
echo ""

echo "Step 3: Running single control test (V-233596)..."
inspec exec . \
    --input-file="$INPUTS_FILE" \
    --controls=V-233596 \
    --reporter=cli || { echo "Single control test failed!"; exit 1; }
echo "✓ Single control test passed"
echo ""

echo "Step 4: Running full profile..."
inspec exec . \
    --input-file="$INPUTS_FILE" \
    --reporter=cli json:"$RESULTS_DIR/results-pg17-$TIMESTAMP.json"
echo "✓ Full profile execution completed"
echo ""

echo "Step 5: Generating summary..."
cat "$RESULTS_DIR/results-pg17-$TIMESTAMP.json" | jq '.profiles[0].summary'
echo ""

echo "=== Test Complete ==="
echo "Results saved to: $RESULTS_DIR/results-pg17-$TIMESTAMP.json"
echo "Upload to Heimdall: https://heimdall-lite.mitre.org/"
```

Make it executable and run:

```bash
chmod +x test-pg17.sh
./test-pg17.sh
```

---

## Reporting Results

### Generate Test Report

```bash
# Create summary report
cat > test-report-pg17.md <<EOF
# PostgreSQL 17.8 STIG Test Report

**Date:** $(date)
**Profile Version:** 3.2.0
**PostgreSQL Version:** 17.8
**Tester:** $(whoami)

## Summary

\`\`\`json
$(cat results-pg17.json | jq '.profiles[0].summary')
\`\`\`

## Key Findings

### Passed Controls
$(cat results-pg17.json | jq -r '.profiles[0].controls[] | select(.results[0].status == "passed") | "- " + .id + ": " + .title' | head -20)

### Failed Controls
$(cat results-pg17.json | jq -r '.profiles[0].controls[] | select(.results[0].status == "failed") | "- " + .id + ": " + .title')

### Skipped Controls
$(cat results-pg17.json | jq -r '.profiles[0].controls[] | select(.results[0].status == "skipped") | "- " + .id + ": " + (.results[0].skip_message // "No message")' | head -10)

## Recommendations

[Add your recommendations here]

## Conclusion

[Add your conclusion here]
EOF

echo "Report generated: test-report-pg17.md"
```

---

## Next Steps After Testing

1. **Review Results**
   - Analyze pass/fail rates
   - Investigate unexpected failures
   - Document exceptions

2. **Address Findings**
   - Fix configuration issues
   - Update RDS parameters
   - Document accepted risks

3. **Production Readiness**
   - Complete all tests successfully
   - Document all exceptions
   - Get security team approval
   - Update runbooks

4. **Continuous Monitoring**
   - Schedule regular scans
   - Automate testing in CI/CD
   - Monitor for drift
   - Update profile as needed

---

## Support

If you encounter issues:
1. Check this testing guide
2. Review [POSTGRESQL_17_UPGRADE.md](POSTGRESQL_17_UPGRADE.md)
3. Check [FIXES_APPLIED.md](FIXES_APPLIED.md)
4. Open issue on GitHub
5. Contact MITRE SAF team

---

**Last Updated:** 2026-10-13  
**Profile Version:** 3.2.0  
**Status:** Ready for Testing
