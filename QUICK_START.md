# Quick Start - Testing PostgreSQL 17.8 STIG Profile

> **Running on Linux or AWS CloudShell?** See [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md) for platform-specific instructions.

## 🚀 Fast Track (5 Minutes)

### 1. Prerequisites Check
```bash
# Check if tools are installed
inspec --version  # Should show InSpec version
psql --version    # Should show PostgreSQL client version
```

**Not installed?**
- **macOS:** `brew install inspec postgresql`
- **Linux/CloudShell:** See [LINUX_CLOUDSHELL_SETUP.md](LINUX_CLOUDSHELL_SETUP.md)
- **Windows:** See [TESTING_GUIDE.md](TESTING_GUIDE.md)

### 2. Create Inputs File
```bash
cd /Users/thomaslord/Work/Coding/git/BAH/TaMIS/aws-rds-crunchy-data-postgresql-stig-baseline

# Copy example and edit
cp inputs-pg17-test.yml.example inputs-pg17-test.yml
nano inputs-pg17-test.yml  # or use your preferred editor
```

**Required changes:**
- `pg_dba_password`: Your database password
- `pg_host`: Your RDS endpoint (e.g., `mydb.abc123.us-east-1.rds.amazonaws.com`)

### 3. Test Connection
```bash
# Quick connectivity test
psql -h YOUR_RDS_ENDPOINT -U postgres -d postgres -c "SELECT version();"
```

### 4. Run Tests
```bash
# Option A: Use the automated script (recommended)
./test-pg17.sh

# Option B: Manual execution
inspec exec . --input-file=inputs-pg17-test.yml --reporter=cli json:results.json
```

### 5. View Results
```bash
# In terminal
cat results.json | jq '.profiles[0].summary'

# Or upload to Heimdall Lite
# Go to: https://heimdall-lite.mitre.org/
# Upload: results.json
```

---

## 📋 What You Need

### Required
- ✅ InSpec installed
- ✅ PostgreSQL client (psql)
- ✅ AWS RDS PostgreSQL 17.8 instance
- ✅ Database credentials
- ✅ Network access to RDS instance

### Optional (but helpful)
- jq (for JSON parsing)
- AWS CLI (for RDS management)
- Heimdall account (for result visualization)

---

## 🎯 Common Commands

### Validate Profile
```bash
inspec check .
```

### Test Single Control
```bash
inspec exec . --input-file=inputs-pg17-test.yml --controls=V-233596 --reporter=cli
```

### Run Full Test
```bash
inspec exec . --input-file=inputs-pg17-test.yml --reporter=cli json:results.json
```

### View Summary
```bash
cat results.json | jq '.profiles[0].summary'
```

### List Failed Controls
```bash
cat results.json | jq -r '.profiles[0].controls[] | select(.results[0].status == "failed") | .id'
```

### Check Specific Control
```bash
cat results.json | jq '.profiles[0].controls[] | select(.id == "V-233596")'
```

---

## 🔧 Troubleshooting

### "Command not found: inspec"
```bash
# Install InSpec
brew install inspec  # macOS
# or
gem install inspec-bin
```

### "Connection refused"
```bash
# Check security group allows your IP on port 5432
# Test with telnet
telnet YOUR_RDS_ENDPOINT 5432
```

### "Authentication failed"
```bash
# Verify credentials
# Check password in inputs-pg17-test.yml
# Try connecting with psql first
```

### "Profile validation failed"
```bash
# Ensure you're in the profile directory
cd /path/to/aws-rds-crunchy-data-postgresql-stig-baseline

# Check Ruby syntax
ruby -c controls/overlay.rb
```

---

## 📊 Expected Results

### Key Controls for PostgreSQL 17

| Control | Check | Expected Result |
|---------|-------|-----------------|
| V-233596 | Password encryption | ✓ PASS (scram-sha-256) |
| V-233569 | Log connections | ✓ PASS (on) |
| V-233598 | pgaudit extension | ✓ PASS (loaded) |
| V-233513 | OS-level security | ↺ SKIP (AWS managed) |

### Typical Results
- **Passed:** 30-50 controls (varies by configuration)
- **Failed:** 0-10 controls (depends on RDS setup)
- **Skipped:** 40-60 controls (AWS-managed + manual review)

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| **QUICK_START.md** | This file - get started fast |
| **TESTING_GUIDE.md** | Comprehensive testing instructions |
| **POSTGRESQL_17_UPGRADE.md** | Detailed upgrade guide |
| **UPDATE_SUMMARY.md** | What changed in v3.2.0 |
| **README.md** | General profile documentation |

---

## 🆘 Getting Help

1. **Check documentation:**
   - [TESTING_GUIDE.md](TESTING_GUIDE.md) - Detailed testing
   - [POSTGRESQL_17_UPGRADE.md](POSTGRESQL_17_UPGRADE.md) - Upgrade info
   - [README.md](README.md) - General usage

2. **Common issues:**
   - Connection problems → Check security groups
   - Auth failures → Verify credentials
   - Control failures → Review RDS configuration

3. **Still stuck?**
   - GitHub Issues: https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline/issues
   - MITRE SAF: saf@groups.mitre.org

---

## ✅ Success Checklist

- [ ] InSpec and psql installed
- [ ] RDS PostgreSQL 17.8 instance available
- [ ] Inputs file created and configured
- [ ] Database connection successful
- [ ] Profile validation passed
- [ ] Tests executed successfully
- [ ] Results reviewed
- [ ] Failures investigated
- [ ] Report generated

---

## 🎓 Next Steps

After successful testing:

1. **Review results** - Analyze pass/fail/skip counts
2. **Address findings** - Fix configuration issues
3. **Document exceptions** - Note accepted risks
4. **Generate report** - Create formal test report
5. **Production deployment** - Roll out to production
6. **Continuous monitoring** - Schedule regular scans

---

## 💡 Pro Tips

1. **Start small:** Test one control first (V-233596)
2. **Use the script:** `./test-pg17.sh` automates everything
3. **Check connectivity:** Always test psql connection first
4. **Save results:** Use timestamps in filenames
5. **Compare versions:** Test against PG 15 and PG 17 to see differences
6. **Use Heimdall:** Visual results are easier to understand
7. **Automate:** Integrate into CI/CD pipeline

---

## 📞 Quick Reference

**Profile Version:** 3.2.0  
**PostgreSQL Support:** 10, 11, 12, 13, 14, 15, 16, 17  
**Last Updated:** 2026-10-13

**Key Files:**
- Profile: `controls/overlay.rb`
- Config: `inspec.yml`
- Inputs: `inputs-pg17-test.yml` (create from .example)
- Test Script: `test-pg17.sh`

**Key Commands:**
```bash
# Validate
inspec check .

# Test
./test-pg17.sh

# Results
cat results.json | jq '.profiles[0].summary'
```

---

**Ready to test? Run:** `./test-pg17.sh`

**Need help? Read:** [TESTING_GUIDE.md](TESTING_GUIDE.md)
