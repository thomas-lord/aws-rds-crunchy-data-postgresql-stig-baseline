# aws-rds-crunchy-data-postgresql-stig-baseline

InSpec profile to validate the secure configuration of AWS RDS-hosted PostgreSQL against the Department of Defense (DoD) [Crunchy Data Postgres 16 Security Technical Implementation Guide (STIG)](https://public.cyber.mil/stigs/).

- Profile Version: **1.0.0**
- STIG: **Crunchy Data Postgres 16** (`CD_Postgres_16_STIG`)
- Benchmark Version: **Version 1 Release 3 (V1R3)**
- Benchmark Date: **01 Jul 2026**
- Benchmark Status: **Accepted** (current)
- **Supported Platforms:** Linux, macOS (InSpec runner); PostgreSQL 16+ target

> [!NOTE]
> This profile targets PostgreSQL **16 and later**. DISA currently publishes two separate STIGs for Crunchy Data PostgreSQL:
> the version-specific **Crunchy Data Postgres 16** STIG (used here) and the general **Crunchy Data PostgreSQL** STIG
> (`CD_PostgreSQL_STIG`, now status **Deprecated** as of V3R2), which covers older engine versions (10-15). If you need to
> assess engines older than 16, use a profile built against the general STIG instead — do not use this profile for those
> versions, as control IDs and requirements differ between the two benchmarks.

> [!NOTE]
> This profile is a **standalone** build: all 111 controls are implemented directly from the published benchmark text
> (title, check, fix, severity, CCI, SRG group, and STIG ID), fetched from the authoritative STIG source. It does not
> `include_controls` from, or otherwise depend on, any third-party InSpec baseline.

## Control Coverage

Of the 111 requirements in V1R3:

| Category | Count | Handling |
|---|---|---|
| Automated SQL/parameter checks | 21 | `SHOW <parameter>` compared against an input-driven expected value |
| pgaudit-based audit checks | 17 | Verifies `pgaudit` is loaded via `shared_preload_libraries` and `pgaudit.log` contains required categories |
| pgcrypto-gated (encryption at rest) | 3 | Verifies `pgcrypto` extension availability when encryption of data at rest is required (input-gated) |
| RDS-specific SSL enforcement | 1 | Checks `rds.force_ssl` as the RDS equivalent of restricting plaintext-adjacent auth methods |
| Vendor-supported version | 1 | Reports `server_version`; flags for manual verification against the current support lifecycle |
| Not Applicable — OS-managed on RDS | 7 | AWS manages the underlying OS/filesystem for RDS; `impact 0.0` with justification |
| Not Applicable — FIPS/kernel-managed on RDS | 3 | No OS/kernel access on RDS to verify FIPS module state; `impact 0.0` with justification |
| Manual review required | 58 | Depends on organizational policy, documented procedures, or artifacts (e.g., SSP, PPSM CAL, CloudWatch/console configuration) that cannot be verified via a SQL session |

Every control's `desc 'check'` and `desc 'fix'` text, along with its severity, CCI, SRG group ID (`gtitle`), and STIG ID
(`stig_id`), is copied verbatim from the published benchmark — nothing here is inferred or fabricated. Only the
*automation* approach (how a check is implemented in InSpec, given AWS RDS's managed-service constraints) reflects
engineering judgment.

## Getting Started

It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps
orchestration server, an administrative management system, or a developer's workstation/laptop) against the target.
This can be any Unix/Linux/macOS runner host with network access to the target RDS instance.

__For the best security of the runner, always install the _latest version_ of InSpec.__

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

### PSQL client setup

InSpec expects the `psql` client to be available on the runner.

```bash
# Linux example
sudo yum install postgresql
which psql
psql --version
```

Test connectivity to your instance from the runner host:

```bash
psql -d postgresql://<master user>:<password>@<endpoint>.rds.amazonaws.com/postgres
```

## Inputs: Tailoring the Scan to Your Environment

The following inputs can be set in an inputs `.yml` file. See [inspec.yml](inspec.yml) for the full list, defaults,
and which controls consume each input. Several inputs capture "organization-defined" values from the STIG text and
must be tailored to your System Security Plan.

```yaml
pg_dba: 'postgres'
pg_dba_password: '<password>'
pg_host: '<endpoint>.rds.amazonaws.com'
pg_db: 'postgres'
pg_port: 5432

pg_superusers: ['rdsadmin']

pg_max_connections: 100
pg_log_line_prefix: '%m [%p]: db=%d,user=%u,app=%a,client=%h '
pg_log_connections: 'on'
pg_log_disconnections: 'on'
pg_log_hostname: 'on'
pg_timezone: 'UTC'
pg_ssl: 'on'
pg_password_encryption: 'scram-sha-256'
pg_client_min_messages: 'error'
pg_log_file_mode: '0600'
pg_tcp_keepalives_idle: '300'
pg_tcp_keepalives_interval: '30'
pg_tcp_keepalives_count: '3'
pg_statement_timeout: '60000'

pgaudit_log_items: ['ddl', 'role', 'read', 'write']
pg_encryption_of_data_at_rest_required: true
```

## Running This Profile

```bash
git clone <this-repo-url>
cd aws-rds-crunchy-data-postgresql-stig-baseline

cp inputs.yml.example inputs.yml   # create and edit with your environment's values
inspec exec . --input-file=inputs.yml --reporter=cli json:results.json
```

## Viewing the JSON Results

The JSON results file can be loaded into [heimdall-lite](https://heimdall-lite.mitre.org/) for an interactive,
graphical view of the InSpec results, or into a full [Heimdall](https://github.com/mitre/heimdall) server for
storing and comparing multiple profile runs.

## Source of Truth

- STIG benchmark content: [DISA Cyber Exchange / public.cyber.mil](https://public.cyber.mil/stigs/) —
  "Crunchy Data Postgres 16 Security Technical Implementation Guide", V1R3, 01 Jul 2026.
- Requirement text (titles, check/fix text, severity, CCI, SRG group, STIG IDs) retrieved programmatically from the
  published benchmark for accuracy; see `controls/*.rb` for the per-control source text.

## Contributing and Getting Help

To report a bug or feature request, please open an issue in this repository.
