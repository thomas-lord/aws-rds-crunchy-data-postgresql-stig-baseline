#!/bin/bash
# AWS CloudShell Quick Start for PostgreSQL 17.8 STIG Testing
# Run this script in CloudShell to set everything up automatically

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  PostgreSQL 17.8 STIG Profile - CloudShell Quick Start    ║${NC}"
echo -e "${BLUE}║  Version 3.2.0                                             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running in CloudShell
if [ -z "$AWS_EXECUTION_ENV" ]; then
    echo -e "${YELLOW}⚠ Warning: This script is optimized for AWS CloudShell${NC}"
    echo -e "${YELLOW}  It may work on other Linux systems but is not guaranteed${NC}"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 1: Install Prerequisites
echo -e "${BLUE}[1/7] Installing prerequisites...${NC}"
echo "This may take 2-3 minutes..."

# Check if already installed
if command -v inspec &> /dev/null && command -v psql &> /dev/null; then
    echo -e "${GREEN}✓ Prerequisites already installed${NC}"
else
    sudo yum install -y ruby ruby-devel gcc make postgresql15 jq git > /dev/null 2>&1
    gem install inspec-bin --no-document > /dev/null 2>&1
    echo -e "${GREEN}✓ Prerequisites installed${NC}"
fi

echo "  - Ruby: $(ruby --version | cut -d' ' -f2)"
echo "  - InSpec: $(inspec --version | head -1 | cut -d' ' -f2)"
echo "  - psql: $(psql --version | cut -d' ' -f3)"
echo ""

# Step 2: Get Profile
echo -e "${BLUE}[2/7] Setting up profile...${NC}"

if [ -d "$HOME/aws-rds-crunchy-data-postgresql-stig-baseline" ]; then
    echo -e "${YELLOW}⚠ Profile directory already exists${NC}"
    read -p "Update from Git? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$HOME/aws-rds-crunchy-data-postgresql-stig-baseline"
        git pull
    fi
else
    cd "$HOME"
    git clone https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline.git
fi

cd "$HOME/aws-rds-crunchy-data-postgresql-stig-baseline"
echo -e "${GREEN}✓ Profile ready${NC}"
echo ""

# Step 3: List RDS Instances
echo -e "${BLUE}[3/7] Finding PostgreSQL RDS instances...${NC}"

RDS_INSTANCES=$(aws rds describe-db-instances \
    --query 'DBInstances[?Engine==`postgres`].[DBInstanceIdentifier,Endpoint.Address,EngineVersion]' \
    --output text 2>/dev/null || echo "")

if [ -z "$RDS_INSTANCES" ]; then
    echo -e "${YELLOW}⚠ No PostgreSQL RDS instances found in this region${NC}"
    echo "Please ensure you have PostgreSQL RDS instances or switch regions"
    echo ""
    read -p "Enter RDS endpoint manually: " RDS_ENDPOINT
    read -p "Enter PostgreSQL version (e.g., 17.8): " PG_VERSION
else
    echo "Found PostgreSQL instances:"
    echo "$RDS_INSTANCES" | nl
    echo ""
    
    # Count instances
    INSTANCE_COUNT=$(echo "$RDS_INSTANCES" | wc -l)
    
    if [ "$INSTANCE_COUNT" -eq 1 ]; then
        RDS_ENDPOINT=$(echo "$RDS_INSTANCES" | awk '{print $2}')
        PG_VERSION=$(echo "$RDS_INSTANCES" | awk '{print $3}')
        echo -e "${GREEN}✓ Using: $RDS_ENDPOINT (v$PG_VERSION)${NC}"
    else
        read -p "Select instance number (1-$INSTANCE_COUNT): " INSTANCE_NUM
        SELECTED=$(echo "$RDS_INSTANCES" | sed -n "${INSTANCE_NUM}p")
        RDS_ENDPOINT=$(echo "$SELECTED" | awk '{print $2}')
        PG_VERSION=$(echo "$SELECTED" | awk '{print $3}')
        echo -e "${GREEN}✓ Selected: $RDS_ENDPOINT (v$PG_VERSION)${NC}"
    fi
fi
echo ""

# Step 4: Get Credentials
echo -e "${BLUE}[4/7] Configuring database credentials...${NC}"

# Check for password in Secrets Manager
echo "Checking AWS Secrets Manager for RDS credentials..."
SECRETS=$(aws secretsmanager list-secrets \
    --query 'SecretList[?contains(Name, `rds`) || contains(Name, `postgres`)].Name' \
    --output text 2>/dev/null || echo "")

if [ -n "$SECRETS" ]; then
    echo "Found secrets:"
    echo "$SECRETS" | tr '\t' '\n' | nl
    echo ""
    read -p "Use a secret? (enter number or 'n' for manual): " SECRET_CHOICE
    
    if [[ "$SECRET_CHOICE" =~ ^[0-9]+$ ]]; then
        SECRET_NAME=$(echo "$SECRETS" | tr '\t' '\n' | sed -n "${SECRET_CHOICE}p")
        RDS_PASSWORD=$(aws secretsmanager get-secret-value \
            --secret-id "$SECRET_NAME" \
            --query SecretString \
            --output text 2>/dev/null)
        
        if [ -n "$RDS_PASSWORD" ]; then
            echo -e "${GREEN}✓ Retrieved password from Secrets Manager${NC}"
        else
            echo -e "${YELLOW}⚠ Could not retrieve secret, enter manually${NC}"
            read -sp "Enter RDS master password: " RDS_PASSWORD
            echo
        fi
    else
        read -sp "Enter RDS master password: " RDS_PASSWORD
        echo
    fi
else
    read -sp "Enter RDS master password: " RDS_PASSWORD
    echo
fi

read -p "Enter RDS master username [postgres]: " RDS_USERNAME
RDS_USERNAME=${RDS_USERNAME:-postgres}

echo -e "${GREEN}✓ Credentials configured${NC}"
echo ""

# Step 5: Test Connection
echo -e "${BLUE}[5/7] Testing database connection...${NC}"

export PGPASSWORD="$RDS_PASSWORD"
if psql -h "$RDS_ENDPOINT" -U "$RDS_USERNAME" -d postgres -c "SELECT version();" > /dev/null 2>&1; then
    ACTUAL_VERSION=$(psql -h "$RDS_ENDPOINT" -U "$RDS_USERNAME" -d postgres -t -c "SHOW server_version;" | xargs)
    echo -e "${GREEN}✓ Connection successful${NC}"
    echo "  PostgreSQL version: $ACTUAL_VERSION"
    
    # Check if version 17
    if [[ $ACTUAL_VERSION == 17* ]]; then
        echo -e "${GREEN}✓ Confirmed PostgreSQL 17.x${NC}"
    else
        echo -e "${YELLOW}⚠ Not PostgreSQL 17.x - results may vary${NC}"
    fi
else
    echo -e "${RED}✗ Connection failed${NC}"
    echo "Please check:"
    echo "  - Security group allows CloudShell IP"
    echo "  - RDS is publicly accessible (or in same VPC)"
    echo "  - Credentials are correct"
    unset PGPASSWORD
    exit 1
fi
unset PGPASSWORD
echo ""

# Step 6: Create Inputs File
echo -e "${BLUE}[6/7] Creating inputs file...${NC}"

cat > inputs-pg17-test.yml <<EOF
# Auto-generated by cloudshell-quickstart.sh
# Date: $(date)

# Connection Settings
pg_dba: '$RDS_USERNAME'
pg_dba_password: '$RDS_PASSWORD'
pg_host: '$RDS_ENDPOINT'
pg_db: 'postgres'
pg_port: 5432

# Version Information
pg_version: '$ACTUAL_VERSION'

# Runner Type
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

# System Resource Users
pg_system_resource_users:
  - "postgres"
  - "rds_superuser"

# System Settings
pg_owner: "postgres"
pg_group: "postgres"

# Extensions
approved_ext:
  - "pgaudit"

# Approved Packages
approved_packages: []

# PostgreSQL Configuration
pg_max_connections: 100
pg_timezone: 'UTC'
pg_ssl: 'on'

# Audit Configuration
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

# Replication
pg_replicas: []

# Object Privileges
pg_object_granted_privileges: 'arwdDxt'
pg_object_public_privileges: 'r'
pg_object_exceptions: []
EOF

echo -e "${GREEN}✓ Inputs file created: inputs-pg17-test.yml${NC}"
echo ""

# Step 7: Run Tests
echo -e "${BLUE}[7/7] Ready to run tests!${NC}"
echo ""
echo "Choose an option:"
echo "  1) Run tests now (recommended)"
echo "  2) Run single control test first (V-233596)"
echo "  3) Exit and run manually later"
echo ""
read -p "Enter choice (1-3): " TEST_CHOICE

case $TEST_CHOICE in
    1)
        echo ""
        echo -e "${BLUE}Running full STIG profile test...${NC}"
        echo "This will take 5-10 minutes..."
        echo ""
        
        chmod +x test-pg17.sh
        ./test-pg17.sh
        ;;
    2)
        echo ""
        echo -e "${BLUE}Running single control test (V-233596 - Password Encryption)...${NC}"
        echo ""
        
        inspec exec . \
            --input-file=inputs-pg17-test.yml \
            --controls=V-233596 \
            --reporter=cli
        
        echo ""
        echo "Single control test complete!"
        echo "To run full test: ./test-pg17.sh"
        ;;
    3)
        echo ""
        echo "Setup complete! To run tests manually:"
        echo "  cd $HOME/aws-rds-crunchy-data-postgresql-stig-baseline"
        echo "  ./test-pg17.sh"
        ;;
    *)
        echo "Invalid choice. Run manually: ./test-pg17.sh"
        ;;
esac

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Setup Complete!                                           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  - Review results in test-results/ directory"
echo "  - Download JSON results: CloudShell > Actions > Download file"
echo "  - Upload to Heimdall: https://heimdall-lite.mitre.org/"
echo ""
echo "Documentation:"
echo "  - QUICK_START.md - Quick reference"
echo "  - LINUX_CLOUDSHELL_SETUP.md - CloudShell details"
echo "  - TESTING_GUIDE.md - Comprehensive guide"
echo ""
