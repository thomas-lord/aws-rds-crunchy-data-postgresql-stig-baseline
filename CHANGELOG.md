# Changelog

All notable changes to the aws-rds-crunchy-data-postgresql-stig-baseline profile will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.2.0] - 2026-10-13

### Added
- PostgreSQL 16.x support
- PostgreSQL 17.x support (including 17.8)
- Version-specific documentation for password encryption in Control V-233596
- Comprehensive upgrade guide: `POSTGRESQL_17_UPGRADE.md`
- This CHANGELOG.md file

### Changed
- Profile version updated from 3.1.0 to 3.2.0
- README.md: Updated supported PostgreSQL versions (10-15 → 10-17)
- README.md: Updated pg_version input example to include 17.8
- inspec.yml: Enhanced description to specify version range
- controls/overlay.rb: Added version notes to Control V-233596

### Fixed
- **CRITICAL:** Line 1121 - Missing comma in `sql.query()` method call (Control V-233597)
- Line 203 - Typo: "reveiwed" → "reviewed" (Control V-233523)
- Line 159 - Typo: "pg_catelog" → "pg_catalog" (Control V-233523)

### Deprecated
- None

### Removed
- None

### Security
- No security-related changes
- All password encryption methods remain secure (scram-sha-256 recommended)

---

## [3.1.0] - 2024-07-24

### Initial Release
- InSpec profile for AWS RDS PostgreSQL STIG compliance
- Support for PostgreSQL versions 10, 11, 12, 13, 14, 15
- Based on Crunchy Data PostgreSQL STIG Baseline V3R1
- Benchmark Date: 24 Jul 2024
- Implements DISA STIG controls for AWS RDS environment
- Skips OS-level controls managed by AWS
- Supports both Windows and Linux InSpec runners

---

## Version Comparison

| Version | Release Date | PostgreSQL Support | Key Features |
|---------|-------------|-------------------|--------------|
| 3.2.0 | 2026-10-13 | 10-17 | Added PG 16/17 support, bug fixes |
| 3.1.0 | 2024-07-24 | 10-15 | Initial release |

---

## Upgrade Path

### From 3.1.0 to 3.2.0

**Breaking Changes:** None - fully backward compatible

**Steps:**
1. Update profile files (or pull latest from repository)
2. Review [POSTGRESQL_17_UPGRADE.md](POSTGRESQL_17_UPGRADE.md) if using PostgreSQL 17
3. No changes to input files required
4. Re-run validation tests

**Recommended Actions:**
- Review fixed syntax errors if you had custom modifications
- Test against PostgreSQL 17 if planning to upgrade
- Update your documentation to reflect new version support

---

## Links

- [GitHub Repository](https://github.com/mitre/aws-rds-crunchy-data-postgresql-stig-baseline)
- [DISA STIGs](https://public.cyber.mil/stigs/)
- [InSpec Documentation](https://docs.chef.io/inspec/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [AWS RDS PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html)
