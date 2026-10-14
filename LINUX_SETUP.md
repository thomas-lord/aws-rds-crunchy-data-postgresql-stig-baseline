# Linux Setup Guide

## Overview

This guide provides instructions for running the PostgreSQL 17.8 STIG profile on Linux systems:
- Amazon Linux 2 / Amazon Linux 2023
- RHEL / CentOS
- Ubuntu / Debian

---

---

## Installation by Platform

### Amazon Linux 2 / Amazon Linux 2023

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

### Setup and Run

```bash
# Clone profile
cd ~
git clone https://github.com/YOUR_ORG/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

# Create inputs file
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml
# Update: pg_dba_password and pg_host

# Run tests
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
git clone https://github.com/YOUR_ORG/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml
# Update: pg_dba_password and pg_host

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
git clone https://github.com/YOUR_ORG/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

cp inputs-pg17-test.yml.example inputs-pg17-test.yml
nano inputs-pg17-test.yml  # or vi
# Update: pg_dba_password and pg_host

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

## Running Tests

After installation, set up and run the profile:

```bash
# Clone profile
cd ~
git clone https://github.com/YOUR_ORG/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline

# Create inputs file
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
vi inputs-pg17-test.yml
# Update: pg_dba_password and pg_host

# Test database connection
psql -h your-rds-endpoint -U postgres -d postgres -c "SELECT version();"

# Run tests
chmod +x test-pg17.sh
./test-pg17.sh

# View results
cat test-results/results-pg17-*.json | jq '.profiles[0].summary'
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

## Troubleshooting

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

## Best Practices

### 1. Use IAM Authentication (Optional)

```bash
# Generate auth token (IAM authentication)
TOKEN=$(aws rds generate-db-auth-token \
    --hostname your-instance.region.rds.amazonaws.com \
    --port 5432 \
    --username postgres \
    --region us-east-1)

# Connect with token (set password inline)
psql "postgresql://postgres:$TOKEN@your-instance.region.rds.amazonaws.com:5432/postgres"
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

**Last Updated:** 2026-10-14  
**Profile Version:** 3.2.0  
**Tested On:** Amazon Linux 2023, RHEL 8/9, Ubuntu 22.04
