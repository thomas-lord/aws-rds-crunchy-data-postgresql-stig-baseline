# Testing Platforms - Quick Reference

## Choose Your Platform

| Platform | Setup Time | Difficulty | Best For | Guide |
|----------|-----------|------------|----------|-------|
| **AWS CloudShell** | 2-3 min | ⭐ Easy | Quick testing, AWS-native | [README_CLOUDSHELL.md](README_CLOUDSHELL.md) |
| **Linux (EC2/VM)** | 5-10 min | ⭐⭐ Medium | Automated/scheduled scans | [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md) |
| **macOS** | 5 min | ⭐ Easy | Local development | [QUICK_START.md](QUICK_START.md) |


---

## AWS CloudShell (Recommended)

### ✅ Advantages
- No installation on local machine
- Pre-configured AWS credentials
- Network access to RDS instances
- Free to use
- Persistent storage (1GB)

### ❌ Limitations
- 20-minute session timeout
- Limited to AWS regions
- 1GB storage limit

### Quick Start

```bash
# One command setup
curl -sSL https://raw.githubusercontent.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/main/cloudshell-quickstart.sh | bash
```

**Documentation:** [README_CLOUDSHELL.md](README_CLOUDSHELL.md)

---

## Linux (Amazon Linux / RHEL / Ubuntu)

### ✅ Advantages
- Full control over environment
- Can run long tests
- Ideal for automation
- Can schedule with cron

### ❌ Limitations
- Requires manual setup
- Need to manage dependencies
- Network configuration required

### Quick Start

```bash
# Amazon Linux 2023
sudo yum install -y ruby ruby-devel gcc make postgresql15 jq git
gem install inspec-bin --no-document

# Ubuntu/Debian
sudo apt-get install -y ruby ruby-dev postgresql-client jq git
gem install inspec-bin --no-document

# Clone and run
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline
./cloudshell-quickstart.sh
```

**Documentation:** [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md)

---

## macOS

### ✅ Advantages
- Easy with Homebrew
- Good for development
- Full-featured terminal

### ❌ Limitations
- Requires local installation
- Network access to RDS needed

### Quick Start

```bash
# Install prerequisites
brew install inspec postgresql jq

# Clone and configure
git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
cd aws-rds-crunchy-data-postgresql-stig-baseline
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
# Edit inputs-pg17-test.yml with your credentials

# Run tests
./test-pg17.sh
```

**Documentation:** [QUICK_START.md](QUICK_START.md)

---

## Docker Container

### ✅ Advantages
- Consistent environment
- No local dependencies
- Easy cleanup

### ❌ Limitations
- Requires Docker
- Network configuration

### Quick Start

```bash
# Build container
docker build -t postgres-stig-tester .

# Run tests
docker run -it --rm \
    -v $(pwd)/test-results:/profile/test-results \
    -v $(pwd)/inputs-pg17-test.yml:/profile/inputs-pg17-test.yml \
    postgres-stig-tester \
    ./test-pg17.sh
```

**Documentation:** [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md#running-in-docker-container)

---

## Platform Comparison

### Installation Complexity

| Platform | Ruby | InSpec | psql | jq | Total Time |
|----------|------|--------|------|----|-----------:|
| CloudShell | Auto | ✓ | ✓ | ✓ | 2-3 min |
| Amazon Linux | ✓ | ✓ | ✓ | ✓ | 5 min |
| macOS | ✓ | ✓ | ✓ | ✓ | 5 min |
| Ubuntu | ✓ | ✓ | ✓ | ✓ | 5-10 min |

### Feature Support

| Feature | CloudShell | Linux | macOS |
|---------|-----------|-------|-------|
| Automated script | ✅ | ✅ | ✅ |
| All controls | ✅ | ✅ | ✅ |
| Secrets Manager | ✅ | ✅ | ✅ |
| Long-running tests | ⚠️ Use screen | ✅ | ✅ |
| Scheduled scans | ❌ | ✅ | ✅ |

---

## Recommendations by Use Case

### Quick One-Time Test
**→ AWS CloudShell**
- Fastest setup
- No local installation
- One command: `./cloudshell-quickstart.sh`

### Regular Compliance Scanning
**→ Linux EC2 Instance**
- Reliable and persistent
- Can schedule with cron
- Integrate with CI/CD

### Development & Testing
**→ macOS or Linux Workstation**
- Full control
- Easy debugging
- Good for profile development

### Enterprise Environment
**→ Linux + Automation**
- EC2 instance with Systems Manager
- EventBridge for scheduling
- S3 for result storage
- SNS for notifications



---

## Network Requirements

All platforms need network access to RDS:

### Security Group Configuration

```bash
# Allow from specific IP
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxxxxx \
    --protocol tcp \
    --port 5432 \
    --cidr YOUR_IP/32

# Allow from VPC CIDR (for EC2/CloudShell)
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxxxxx \
    --protocol tcp \
    --port 5432 \
    --cidr 10.0.0.0/16
```

### Test Connectivity

```bash
# All platforms
telnet your-rds-endpoint 5432

# Or with nc
nc -zv your-rds-endpoint 5432

# Or with psql
psql -h your-rds-endpoint -U postgres -d postgres -c "SELECT 1;"
```

---

## Documentation Map

```
Start Here
    ↓
┌─────────────────────────────────────────────┐
│  What platform are you using?              │
├─────────────────────────────────────────────┤
│  AWS CloudShell → README_CLOUDSHELL.md     │
│  Linux/EC2      → LINUX_CLOUDSHELL_SETUP.md│
│  macOS          → QUICK_START.md            │
│  Any Platform   → QUICK_START.md            │
└─────────────────────────────────────────────┘
    ↓
Need More Details?
    ↓
┌─────────────────────────────────────────────┐
│  Comprehensive Testing → TESTING_GUIDE.md   │
│  PostgreSQL 17 Info    → POSTGRESQL_17_...  │
│  What Changed          → UPDATE_SUMMARY.md  │
│  Version History       → CHANGELOG.md       │
└─────────────────────────────────────────────┘
```

---

## Quick Commands by Platform

### AWS CloudShell
```bash
./cloudshell-quickstart.sh
```

### Linux
```bash
# Setup
sudo yum install -y ruby ruby-devel gcc make postgresql15 jq git
gem install inspec-bin --no-document

# Run
./test-pg17.sh
```

### macOS
```bash
# Setup
brew install inspec postgresql jq

# Run
./test-pg17.sh
```

---

## Getting Help

### Platform-Specific Issues

| Platform | Check First | Documentation |
|----------|------------|---------------|
| CloudShell | [README_CLOUDSHELL.md](README_CLOUDSHELL.md) | Troubleshooting section |
| Linux | [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md) | Platform-specific setup |
| macOS | [QUICK_START.md](QUICK_START.md) | Troubleshooting section |

### General Support

- **GitHub Issues:** https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/issues
- **MITRE SAF:** saf@groups.mitre.org
- **Documentation:** See README.md for full documentation list

---

**Profile Version:** 3.2.0  
**Last Updated:** 2026-10-13  
**Supported Platforms:** CloudShell, Amazon Linux, RHEL, Ubuntu, macOS
