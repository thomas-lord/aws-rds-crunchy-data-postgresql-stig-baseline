# Linux / AWS CloudShell Setup Guide

## Overview

This guide provides instructions for running the PostgreSQL 17.8 STIG profile from:
- AWS CloudShell
- Amazon Linux 2 / Amazon Linux 2023
- RHEL / CentOS
- Ubuntu / Debian

---

## Quick Start - AWS CloudShell (Fastest)

AWS CloudShell comes pre-configured with AWS CLI and has network access to your RDS instances.

### 1. Open CloudShell

```bash
# In AWS Console, click the CloudShell icon (>_) in the top navigation bar
# Or go to: https://console.aws.amazon.com/cloudshell
```

### 2. Install Prerequisites

```bash
# Install Ruby (required for InSpec)
sudo yum install -y ruby ruby-devel gcc make

# Install InSpec
gem install inspec-bin --no-document

# Install PostgreSQL client
sudo yum install -y postgresql15

# Install jq for JSON parsing
sudo yum install -y jq

# Verify installations
inspec --version
psql --version
jq --version
```

### 3. Clone or Upload Profile

**Option A: Clone from Git**
```bash
cd ~
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline
```

**Option B: Upload Files**
```bash
# In CloudShell, click Actions > Upload file
# Upload the profile directory as a zip file
cd ~
unzip aws-rds-crunchy-data-postgresql-stig-baseline.zip
cd aws-rds-crunchy-data-postgresql-stig-baseline
```

### 4. Create Inputs File

```bash
# Copy example
cp inputs-pg17-test.yml.example inputs-pg17-test.yml

# Edit with vi or nano
vi inputs-pg17-test.yml
# Press 'i' to insert, edit values, press ESC, type ':wq' to save
```

**Required changes:**
- `pg_dba_password`: Your RDS master password
- `pg_host`: Your RDS endpoint (find in RDS console)

**Get RDS endpoint:**
```bash
# List your RDS instances
aws rds describe-db-instances \
    --query 'DBInstances[*].[DBInstanceIdentifier,Endpoint.Address,EngineVersion]' \
    --output table

# Get specific endpoint
aws rds describe-db-instances \
    --db-instance-identifier your-instance-name \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text
```

### 5. Test Connection

```bash
# Test database connectivity
psql -h your-instance.region.rds.amazonaws.com \
     -U postgres \
     -d postgres \
     -c "SELECT version();"
# Enter password when prompted
```

### 6. Run Tests

```bash
# Make script executable
chmod +x test-pg17.sh

# Run automated test
./test-pg17.sh

# Or run manually
inspec exec . \
    --input-file=inputs-pg17-test.yml \
    --reporter=cli json:results-pg17.json
```

### 7. View Results

```bash
# View summary
cat results-pg17.json | jq '.profiles[0].summary'

# Download results file
# In CloudShell: Actions > Download file
# Enter: results-pg17.json
```

---

## Amazon Linux 2 / Amazon Linux 2023

### Installation

```bash
# Update system
sudo yum update -y

# Install Ruby and development tools
sudo yum install -y ruby ruby-devel gcc make gcc-c++ \
    openssl-devel readline-devel zlib-devel

# Install InSpec
sudo gem install inspec-bin --no-document

# Install PostgreSQL client
# For Amazon Linux 2
sudo amazon-linux-extras install postgresql14 -y

# For Amazon Linux 2023
sudo yum install -y postgresql15

# Install jq
sudo yum install -y jq

# Install git (if needed)
sudo yum install -y git
```

### Setup Profile

```bash
# Clone profile
cd /home/ec2-user
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

# Create inputs file
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml
```

### Run Tests

```bash
chmod +x test-pg17.sh
./test-pg17.sh
```

---

## RHEL / CentOS 7/8/9

### Installation

```bash
# Update system
sudo yum update -y

# Install EPEL repository (for additional packages)
sudo yum install -y epel-release

# Install Ruby and development tools
sudo yum install -y ruby ruby-devel gcc make gcc-c++ \
    openssl-devel readline-devel zlib-devel

# Install InSpec
sudo gem install inspec-bin --no-document

# Install PostgreSQL client
# RHEL/CentOS 7
sudo yum install -y postgresql

# RHEL/CentOS 8/9
sudo dnf install -y postgresql

# Install jq
sudo yum install -y jq

# Install git
sudo yum install -y git
```

### Setup and Run

```bash
cd ~
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml

chmod +x test-pg17.sh
./test-pg17.sh
```

---

## Ubuntu / Debian

### Installation

```bash
# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install Ruby and development tools
sudo apt-get install -y ruby ruby-dev build-essential \
    libssl-dev libreadline-dev zlib1g-dev

# Install InSpec
sudo gem install inspec-bin --no-document

# Install PostgreSQL client
sudo apt-get install -y postgresql-client

# Install jq
sudo apt-get install -y jq

# Install git
sudo apt-get install -y git
```

### Setup and Run

```bash
cd ~
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

cp inputs-pg17-test.yml.example inputs-pg17-test.yml
nano inputs-pg17-test.yml  # or vi

chmod +x test-pg17.sh
./test-pg17.sh
```

---

## Using AWS Secrets Manager for Credentials

### Store Password in Secrets Manager

```bash
# Create secret
aws secretsmanager create-secret \
    --name rds/postgres/master-password \
    --description "RDS PostgreSQL master password" \
    --secret-string "REPLACE_WITH_YOUR_ACTUAL_PASSWORD"

# Or update existing secret
aws secretsmanager update-secret \
    --secret-id rds/postgres/master-password \
    --secret-string "REPLACE_WITH_YOUR_ACTUAL_PASSWORD"
```

### Retrieve Password in Script

```bash
# Get password from Secrets Manager
export PG_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id rds/postgres/master-password \
    --query SecretString \
    --output text)

# Use in inputs file with ERB template
cat > inputs-pg17-test.yml <<EOF
pg_dba: 'postgres'
pg_dba_password: '<%= ENV["PG_PASSWORD"] %>'
pg_host: 'your-instance.region.rds.amazonaws.com'
# ... rest of config
EOF

# Run InSpec
inspec exec . --input-file=inputs-pg17-test.yml --reporter=cli json:results.json
```

---

## Network Configuration

### Security Group Setup

Your Linux instance or CloudShell needs network access to RDS:

```bash
# Get your current IP
MYIP=$(curl -s https://checkip.amazonaws.com)
echo "My IP: $MYIP"

# Add inbound rule to RDS security group
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxxxxx \
    --protocol tcp \
    --port 5432 \
    --cidr $MYIP/32

# Or allow from VPC CIDR
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxxxxx \
    --protocol tcp \
    --port 5432 \
    --cidr 10.0.0.0/16
```

### Test Connectivity

```bash
# Test with telnet
telnet your-instance.region.rds.amazonaws.com 5432

# Test with nc (netcat)
nc -zv your-instance.region.rds.amazonaws.com 5432

# Test with psql
psql -h your-instance.region.rds.amazonaws.com \
     -U postgres \
     -d postgres \
     -c "SELECT 1;"
```

---

## Automated Setup Script

Create `setup-linux.sh`:

```bash
#!/bin/bash
# Automated setup for Linux/CloudShell

set -e

echo "=== PostgreSQL STIG Profile Setup for Linux ==="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS $VER"
echo ""

# Install based on OS
case $OS in
    amzn)
        echo "Installing for Amazon Linux..."
        sudo yum install -y ruby ruby-devel gcc make gcc-c++ \
            postgresql15 jq git
        ;;
    rhel|centos)
        echo "Installing for RHEL/CentOS..."
        sudo yum install -y epel-release
        sudo yum install -y ruby ruby-devel gcc make gcc-c++ \
            postgresql jq git
        ;;
    ubuntu|debian)
        echo "Installing for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y ruby ruby-dev build-essential \
            postgresql-client jq git
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Install InSpec
echo ""
echo "Installing InSpec..."
sudo gem install inspec-bin --no-document

# Verify installations
echo ""
echo "Verifying installations..."
echo "Ruby: $(ruby --version)"
echo "InSpec: $(inspec --version | head -1)"
echo "psql: $(psql --version)"
echo "jq: $(jq --version)"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Clone or upload the profile"
echo "2. Create inputs-pg17-test.yml from example"
echo "3. Run: ./test-pg17.sh"
```

Make it executable and run:

```bash
chmod +x setup-linux.sh
./setup-linux.sh
```

---

## Running in Docker Container

If you prefer containerized testing:

```bash
# Create Dockerfile
cat > Dockerfile <<'EOF'
FROM amazonlinux:2023

# Install dependencies
RUN yum update -y && \
    yum install -y ruby ruby-devel gcc make gcc-c++ \
    postgresql15 jq git && \
    gem install inspec-bin --no-document && \
    yum clean all

# Set working directory
WORKDIR /profile

# Copy profile files
COPY . /profile/

# Default command
CMD ["/bin/bash"]
EOF

# Build image
docker build -t postgres-stig-tester .

# Run container
docker run -it --rm \
    -v $(pwd)/test-results:/profile/test-results \
    postgres-stig-tester

# Inside container, run tests
./test-pg17.sh
```

---

## Troubleshooting Linux/CloudShell

### Issue: gem install fails

```bash
# Install Ruby development headers
sudo yum install -y ruby-devel gcc make

# Or on Ubuntu
sudo apt-get install -y ruby-dev build-essential

# Retry InSpec installation
sudo gem install inspec-bin --no-document
```

### Issue: psql not found

```bash
# Amazon Linux 2
sudo amazon-linux-extras install postgresql14

# Amazon Linux 2023 / RHEL
sudo yum install -y postgresql15

# Ubuntu/Debian
sudo apt-get install -y postgresql-client
```

### Issue: Connection timeout

```bash
# Check security group
aws ec2 describe-security-groups \
    --group-ids sg-xxxxxxxxx \
    --query 'SecurityGroups[0].IpPermissions'

# Check RDS is publicly accessible (if needed)
aws rds describe-db-instances \
    --db-instance-identifier your-instance \
    --query 'DBInstances[0].PubliclyAccessible'

# Test from instance
telnet your-rds-endpoint 5432
```

### Issue: Permission denied

```bash
# Make script executable
chmod +x test-pg17.sh

# Or run with bash
bash test-pg17.sh
```

### Issue: InSpec cache errors

```bash
# Clear InSpec cache
rm -rf ~/.inspec/cache

# Re-run test
./test-pg17.sh
```

---

## CloudShell Limitations

### Storage
- CloudShell has 1GB persistent storage in $HOME
- Files outside $HOME are deleted after session ends
- Store profile and results in $HOME

### Session Timeout
- Sessions timeout after 20 minutes of inactivity
- Use `screen` or `tmux` for long-running tests

```bash
# Install screen
sudo yum install -y screen

# Start screen session
screen -S stig-test

# Run tests
./test-pg17.sh

# Detach: Ctrl+A, then D
# Reattach: screen -r stig-test
```

### Network
- CloudShell runs in AWS network
- Has access to private RDS instances in same region
- No additional VPN/bastion needed

---

## Best Practices for Linux/CloudShell

### 1. Use IAM Authentication (Optional)

```bash
# Generate auth token (IAM authentication)
TOKEN=$(aws rds generate-db-auth-token \
    --hostname your-instance.region.rds.amazonaws.com \
    --port 5432 \
    --username postgres \
    --region us-east-1)

# Connect with token
PGPASSWORD=$TOKEN psql -h your-instance.region.rds.amazonaws.com \
     -U postgres \
     -d postgres
```

### 2. Automate with Systems Manager

```bash
# Store as SSM document for automated scanning
aws ssm create-document \
    --name "RDS-STIG-Scan" \
    --document-type "Command" \
    --content file://stig-scan-document.json
```

### 3. Schedule with EventBridge

```bash
# Run weekly scans using EventBridge + Lambda
# Lambda function triggers EC2 instance to run scan
```

### 4. Store Results in S3

```bash
# Upload results to S3
aws s3 cp results-pg17.json \
    s3://your-compliance-bucket/stig-results/$(date +%Y%m%d)/

# Set lifecycle policy for retention
aws s3api put-bucket-lifecycle-configuration \
    --bucket your-compliance-bucket \
    --lifecycle-configuration file://lifecycle.json
```

---

## Example: Complete CloudShell Workflow

```bash
# 1. Open CloudShell in AWS Console

# 2. Install prerequisites
sudo yum install -y ruby ruby-devel gcc make postgresql15 jq
gem install inspec-bin --no-document

# 3. Clone profile
cd ~
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

# 4. Get RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier your-pg17-instance \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text)

echo "RDS Endpoint: $RDS_ENDPOINT"

# 5. Get password from Secrets Manager
RDS_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id rds/postgres/password \
    --query SecretString \
    --output text)

# 6. Create inputs file
cat > inputs-pg17-test.yml <<EOF
pg_dba: 'postgres'
pg_dba_password: '$RDS_PASSWORD'
pg_host: '$RDS_ENDPOINT'
pg_db: 'postgres'
pg_port: 5432
pg_version: '17.8'
windows_runner: false
pg_users: ["postgres", "rds_iam", "rds_superuser", "rdsadmin"]
pg_superusers: ["rdsadmin"]
rds_superusers: ["postgres"]
pg_system_resource_users: ["postgres", "rds_superuser"]
pg_owner: "postgres"
pg_group: "postgres"
approved_ext: ["pgaudit"]
approved_packages: []
pg_max_connections: 100
pg_timezone: 'UTC'
pg_ssl: 'on'
pgaudit_log_items: ['ddl', 'role', 'read', 'write']
pgaudit_log_line_items: ['%m', '%u', '%c', '%d', '%p', '%r']
pg_replicas: []
pg_object_granted_privileges: 'arwdDxt'
pg_object_public_privileges: 'r'
pg_object_exceptions: []
EOF

# 7. Test connection
psql -h $RDS_ENDPOINT -U postgres -d postgres -c "SELECT version();"

# 8. Run tests
chmod +x test-pg17.sh
./test-pg17.sh

# 9. View results
cat test-results/results-pg17-*.json | jq '.profiles[0].summary'

# 10. Upload to S3
aws s3 cp test-results/results-pg17-*.json \
    s3://your-bucket/stig-results/$(date +%Y%m%d)/

# 11. Download for Heimdall (optional)
# CloudShell: Actions > Download file
# Enter: test-results/results-pg17-<timestamp>.json
```

---

## Quick Reference - Linux Commands

```bash
# Installation
sudo yum install -y ruby ruby-devel gcc make postgresql15 jq  # Amazon Linux
sudo apt-get install -y ruby ruby-dev postgresql-client jq    # Ubuntu
gem install inspec-bin --no-document

# Setup
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml

# Test
chmod +x test-pg17.sh
./test-pg17.sh

# Results
cat results-pg17.json | jq '.profiles[0].summary'
```

---

## Support

**Documentation:**
- [QUICK_START.md](QUICK_START.md) - General quick start
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Comprehensive testing
- [POSTGRESQL_17_UPGRADE.md](POSTGRESQL_17_UPGRADE.md) - Upgrade guide

**Help:**
- GitHub Issues: https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/issues
- MITRE SAF: saf@groups.mitre.org

---

**Last Updated:** 2026-10-13  
**Profile Version:** 3.2.0  
**Tested On:** Amazon Linux 2023, RHEL 8/9, Ubuntu 22.04, AWS CloudShell
