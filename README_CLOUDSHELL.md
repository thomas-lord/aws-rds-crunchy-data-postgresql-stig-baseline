# AWS CloudShell - One Command Setup

## 🚀 Fastest Way to Test PostgreSQL 17.8 STIG Compliance

### One-Line Setup

Open AWS CloudShell and run:

```bash
curl -sSL https://raw.githubusercontent.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/main/cloudshell-quickstart.sh | bash
```

Or if you have the repository locally:

```bash
cd ~
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline
./cloudshell-quickstart.sh
```

### What It Does

The script automatically:
1. ✅ Installs InSpec, PostgreSQL client, and dependencies
2. ✅ Finds your PostgreSQL RDS instances
3. ✅ Retrieves credentials from Secrets Manager (optional)
4. ✅ Tests database connectivity
5. ✅ Creates configuration file
6. ✅ Runs STIG compliance tests
7. ✅ Generates results

### Requirements

- AWS CloudShell access
- PostgreSQL RDS instance (any version, optimized for 17.x)
- RDS master credentials
- Security group allowing CloudShell access to RDS

### Time Required

- **Setup:** 2-3 minutes
- **Testing:** 5-10 minutes
- **Total:** ~10-15 minutes

---

## Manual Setup (If You Prefer)

### Step 1: Install Prerequisites

```bash
sudo yum install -y ruby ruby-devel gcc make postgresql15 jq git
gem install inspec-bin --no-document
```

### Step 2: Get Profile

```bash
cd ~
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline
```

### Step 3: Configure

```bash
# Find your RDS endpoint
aws rds describe-db-instances \
    --query 'DBInstances[*].[DBInstanceIdentifier,Endpoint.Address,EngineVersion]' \
    --output table

# Create inputs file
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml
# Update: pg_dba_password and pg_host
```

### Step 4: Test

```bash
# Test connection
psql -h your-instance.region.rds.amazonaws.com -U postgres -d postgres -c "SELECT version();"

# Run tests
./test-pg17.sh
```

### Step 5: View Results

```bash
# Summary
cat test-results/results-pg17-*.json | jq '.profiles[0].summary'

# Download results
# CloudShell > Actions > Download file
# Enter: test-results/results-pg17-<timestamp>.json

# Upload to Heimdall
# https://heimdall-lite.mitre.org/
```

---

## CloudShell Tips

### Persistent Storage

CloudShell provides 1GB persistent storage in `$HOME`:

```bash
# Store profile and results in $HOME
cd $HOME
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git

# Results persist across sessions
ls ~/aws-rds-crunchy-data-postgresql-stig-baseline/test-results/
```

### Long-Running Tests

Use `screen` for tests that take longer than 20 minutes:

```bash
# Install screen
sudo yum install -y screen

# Start session
screen -S stig-test

# Run tests
./test-pg17.sh

# Detach: Ctrl+A, then D
# Reattach later: screen -r stig-test
```

### Network Access

CloudShell runs in AWS network and can access:
- ✅ Public RDS instances
- ✅ Private RDS instances in same region
- ✅ VPC endpoints
- ❌ On-premises databases (without VPN)

### File Transfer

**Download results:**
```bash
# CloudShell > Actions > Download file
# Enter filename: test-results/results-pg17-<timestamp>.json
```

**Upload files:**
```bash
# CloudShell > Actions > Upload file
# Select your file
```

### Region Selection

CloudShell region = RDS region:

```bash
# Check current region
aws configure get region

# List RDS instances in current region
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# Switch region in CloudShell settings if needed
```

---

## Secrets Manager Integration

### Store RDS Password

```bash
# Create secret
aws secretsmanager create-secret \
    --name rds/postgres/master-password \
    --secret-string "REPLACE_WITH_YOUR_ACTUAL_PASSWORD"

# Update secret
aws secretsmanager update-secret \
    --secret-id rds/postgres/master-password \
    --secret-string "NewPassword456!"
```

### Use in Testing

The `cloudshell-quickstart.sh` script automatically detects and offers to use Secrets Manager credentials.

Manual usage:

```bash
# Retrieve password
export PG_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id rds/postgres/master-password \
    --query SecretString \
    --output text)

# Use in inputs file
cat > inputs-pg17-test.yml <<EOF
pg_dba_password: '$PG_PASSWORD'
# ... rest of config
EOF
```

---

## Troubleshooting

### "Command not found: inspec"

```bash
# Reinstall
gem install inspec-bin --no-document

# Check PATH
echo $PATH
export PATH=$PATH:~/.gem/ruby/bin
```

### "Connection refused"

```bash
# Check security group
aws ec2 describe-security-groups --group-ids sg-xxxxxxxxx

# Get CloudShell IP (not always reliable)
curl -s https://checkip.amazonaws.com

# Better: Allow from VPC CIDR or use VPC endpoint
```

### "Authentication failed"

```bash
# Verify credentials
aws secretsmanager get-secret-value \
    --secret-id rds/postgres/master-password \
    --query SecretString \
    --output text

# Test manually
psql -h your-endpoint -U postgres -d postgres
```

### "Profile validation failed"

```bash
# Check Ruby syntax
ruby -c controls/overlay.rb

# Validate profile
inspec check .

# Clear cache
rm -rf ~/.inspec/cache
```

---

## Automated Scanning

### Schedule with EventBridge

Create Lambda function to trigger CloudShell command:

```python
import boto3

def lambda_handler(event, context):
    ssm = boto3.client('ssm')
    
    # Run command in EC2 instance (not CloudShell directly)
    response = ssm.send_command(
        InstanceIds=['i-xxxxxxxxx'],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands': [
                'cd /home/ec2-user/aws-rds-crunchy-data-postgresql-stig-baseline',
                './test-pg17.sh',
                'aws s3 cp test-results/*.json s3://compliance-bucket/'
            ]
        }
    )
    
    return response
```

### Store Results in S3

```bash
# Upload after each test
aws s3 cp test-results/results-pg17-*.json \
    s3://your-compliance-bucket/stig-results/$(date +%Y%m%d)/

# Set lifecycle policy
aws s3api put-bucket-lifecycle-configuration \
    --bucket your-compliance-bucket \
    --lifecycle-configuration '{
        "Rules": [{
            "Id": "DeleteOldResults",
            "Status": "Enabled",
            "Expiration": {"Days": 90}
        }]
    }'
```

---

## Quick Reference

### Essential Commands

```bash
# Setup (one-time)
./cloudshell-quickstart.sh

# Run tests
./test-pg17.sh

# View summary
cat test-results/results-pg17-*.json | jq '.profiles[0].summary'

# List failed controls
cat test-results/results-pg17-*.json | jq -r '.profiles[0].controls[] | select(.results[0].status == "failed") | .id'

# Check specific control
cat test-results/results-pg17-*.json | jq '.profiles[0].controls[] | select(.id == "V-233596")'
```

### File Locations

```bash
# Profile directory
cd ~/aws-rds-crunchy-data-postgresql-stig-baseline

# Configuration
cat inputs-pg17-test.yml

# Results
ls -lh test-results/

# Logs
ls -lh ~/.inspec/
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| **README_CLOUDSHELL.md** | This file - CloudShell quick start |
| **LINUX_CLOUDSHELL_SETUP.md** | Detailed Linux/CloudShell setup |
| **QUICK_START.md** | General quick start (all platforms) |
| **TESTING_GUIDE.md** | Comprehensive testing guide |
| **POSTGRESQL_17_UPGRADE.md** | PostgreSQL 17 upgrade details |

---

## Support

**Quick Help:**
- Check [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md) for detailed troubleshooting
- Review [TESTING_GUIDE.md](TESTING_GUIDE.md) for comprehensive guidance

**Issues:**
- GitHub: https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/issues
- Email: saf@groups.mitre.org

---

**Profile Version:** 3.2.0  
**PostgreSQL Support:** 10, 11, 12, 13, 14, 15, 16, 17  
**Last Updated:** 2026-10-13  
**Optimized For:** AWS CloudShell, Amazon Linux 2023
