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

This profile uses a **hybrid** automation approach: most checks run entirely over the PostgreSQL SQL session, but a
subset of controls ask about facts that only exist on the AWS side (RDS configuration, security groups, CloudWatch
alarms, pending maintenance) — those are checked via the **AWS CLI** (`aws rds`, `aws ec2`, `aws cloudwatch`)
instead of being left as pure manual review.

Of the 111 requirements in V1R3:

| Category | Count | Handling |
|---|---|---|
| pgaudit-based audit checks | 29 | Verifies `pgaudit` is loaded via `shared_preload_libraries` and `pgaudit.log` contains required categories |
| Automated SQL/parameter checks | 23 | `SHOW <parameter>` compared against an input-driven expected value |
| Manual review required | 34 | Depends on organizational policy, documented procedures, or artifacts (e.g., SSP, PPSM CAL, console configuration) that no tool — SQL or AWS CLI — can resolve on its own |
| Not Applicable — OS-managed on RDS | 8 | AWS manages the underlying OS, filesystem, and package/binary lifecycle for RDS; `impact 0.0` with justification |
| Not Applicable — FIPS/kernel-managed on RDS | 3 | No OS/kernel access on RDS to verify FIPS module state; `impact 0.0` with justification |
| pgcrypto-gated (encryption at rest) | 3 | Verifies `pgcrypto` extension availability when encryption of data at rest is required (input-gated) |
| **AWS CLI: security group exposure** | 2 | `aws ec2 describe-security-groups` on the instance's VPC SGs — flags any `0.0.0.0/0` ingress rule (V-261889, V-261926) |
| **AWS CLI: CloudWatch Logs export** | 2 | `aws rds describe-db-instances` — confirms `postgresql` is in `EnabledCloudwatchLogsExports` (RDS's equivalent of centralized/syslog logging) (V-261917, V-261967) |
| Superuser privilege check (SQL) | 1 | Queries `pg_roles` for `rolsuper` and compares against `pg_superusers`; schema/table grant review flagged manual (V-261924) |
| **AWS CLI: IAM database authentication** | 1 | `aws rds describe-db-instances` — confirms `IAMDatabaseAuthenticationEnabled` (V-261858) |
| RDS-specific SSL enforcement (SQL) | 1 | Checks `rds.force_ssl`, the RDS equivalent of restricting plaintext-adjacent auth methods (V-261892) |
| **AWS CLI: storage capacity** | 1 | `aws rds describe-db-instances` — reports `AllocatedStorage`/`MaxAllocatedStorage` for storage-autoscaling headroom review (V-261918) |
| **AWS CLI: storage alarm presence** | 1 | `aws cloudwatch describe-alarms-for-metric` — confirms a `FreeStorageSpace` alarm exists (V-261919) |
| **AWS CLI: patch timeliness** | 1 | `aws rds describe-db-instances` + `describe-pending-maintenance-actions` — flags any pending/overdue maintenance (V-261936) |
| Vendor-supported version (SQL) | 1 | Reports `server_version`; flags for manual verification against the current support lifecycle |

Every control's `desc 'check'` and `desc 'fix'` text, along with its severity, CCI, SRG group ID (`gtitle`), and STIG ID
(`stig_id`), is copied verbatim from the published benchmark — nothing here is inferred or fabricated. Only the
*automation* approach (how a check is implemented, given AWS RDS's managed-service constraints) reflects engineering
judgment, and every AWS CLI-based control still includes a `describe` block flagging any residual manual-review
aspect it doesn't fully resolve (e.g., whether a given CIDR is actually PPSM-approved).

### AWS CLI prerequisites

Controls tagged "AWS CLI" above require:
- The `aws` CLI installed on the runner, authenticated with read-only IAM permissions
  (`rds:DescribeDBInstances`, `rds:DescribePendingMaintenanceActions`, `ec2:DescribeSecurityGroups`,
  `cloudwatch:DescribeAlarmsForMetric`).
- The `aws_db_instance_identifier` input set to the RDS **DB instance identifier** (not the connection endpoint).
- Optionally `aws_region` / `aws_cli_profile` if not relying on the runner's default AWS configuration.

If the AWS CLI isn't installed/configured or `aws_db_instance_identifier` is left blank, these controls are
skipped (`only_if`) rather than reported as failing, so the profile still runs cleanly SQL-only when AWS access
isn't available.

### Connection auto-discovery

All SQL-based controls connect via a shared `aws_rds_connection` resource (see `libraries/aws_rds_connection.rb`)
that resolves `pg_host`, `pg_port`, `pg_db`, and `pg_dba` from `aws rds describe-db-instances`
(`Endpoint.Address`, `Endpoint.Port`, `DBName`, `MasterUsername`) whenever `aws_db_instance_identifier` is set and
the AWS CLI is available — the manual `pg_host`/`pg_port`/`pg_db`/`pg_dba` inputs are then only used as a fallback
(e.g., when connecting through a bastion/different hostname than the RDS endpoint, or without AWS CLI access).
**`pg_dba_password` is never discoverable this way and must always be supplied manually** — it's a secret the AWS
API has no way to return.

Every SQL-based control that connects this way also adds a secondary check of the DB instance's parameter group
`ParameterApplyStatus`: if it's `pending-reboot`, the control still reports the true *live* SQL `SHOW` result as
the primary finding, but flags that some parameter-group change may not yet be reflected in that live value —
belt-and-suspenders rather than trusting the parameter group alone.

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

In most cases, the only thing you need to configure is **database connection info**. Every other input already has
a STIG-aligned default in [inspec.yml](inspec.yml) and is otherwise derived at run time from the live database
(SQL `SHOW`) or from AWS (the `aws` CLI) — see "Connection auto-discovery" above and "Control Coverage" below. You
only need to override a default if your organization's documented System Security Plan actually specifies a
different value than the STIG default.

### Required

```yaml
# Recommended: AWS CLI auto-discovers pg_host/pg_port/pg_db/pg_dba for you.
aws_db_instance_identifier: '<rds-db-instance-id>'
aws_region: 'us-east-1'

# Always manual -- the AWS API cannot return this secret.
pg_dba_password: '<password>'
```

### Manual connection fallback

Only needed if `aws_db_instance_identifier` is left blank or the AWS CLI isn't available to the runner; otherwise
these are overridden automatically by AWS CLI discovery.

```yaml
pg_dba: 'postgres'
pg_host: '<endpoint>.rds.amazonaws.com'
pg_db: 'postgres'
pg_port: 5432
aws_cli_profile: ''
```

### Optional policy overrides

Each of these already has a STIG-aligned default; only set one if your SSP requires something different.

```yaml
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
pgaudit_log_items: ['ddl', 'role', 'read', 'write']
pg_encryption_of_data_at_rest_required: true
pg_storage_alarm_threshold_percent: 75
pg_approved_ingress_cidrs: []
```

See [inspec.yml](inspec.yml) for the full, authoritative input list (with descriptions and which controls consume
each one) and [inputs.yml.example](inputs.yml.example) for a ready-to-copy starting file.

## Running This Profile

```bash
git clone <this-repo-url>
cd aws-rds-crunchy-data-postgresql-stig-baseline

cp inputs.yml.example inputs.yml   # create and edit with your environment's values
inspec exec . --input-file=inputs.yml --reporter=cli json:results.json
```

## Producing an ATO Checklist (.ckl) for eMASS

`inspec exec` produces results in Heimdall Data Format (HDF) JSON — not directly an eMASS/STIG-Viewer `.ckl` file.
To get a `.ckl`, convert the HDF output with the free, open-source `saf` CLI (no MITRE account/affiliation
required):

```bash
# One-time install
npm install -g @mitre/saf

# Convert the InSpec results from "Running This Profile" above into a .ckl
saf convert hdf2ckl -i results.json -o results.ckl \
  --hostname <asset-hostname> --fqdn <asset-fqdn> --ip <asset-ip>
```

`saf convert hdf2ckl` builds the checklist directly from the HDF file's embedded control metadata — the
`stig_id`/`gid` (Vuln ID)/`cci`/`severity` tags already present on every control in this profile — so no separate
blank `.ckl` template is required. Pass `-m <metadata.json>` (generate a starting file with
`saf generate ckl_metadata -o metadata.json`) if you need to set additional asset/STIG metadata fields (role,
tech area, classification marking, etc.) beyond the `--hostname`/`--fqdn`/`--ip`/`--mac` flags.

> [!NOTE]
> This STIG has no DISA-published SCAP/OVAL content — DISA distributes it as a "Manual STIG" (XCCDF with
> check/fix text only, no automated OVAL probes), which is why a SCAP Compliance Checker (SCC) scan isn't an
> option here. InSpec plus this `hdf2ckl` conversion is the practical path to an eMASS-importable checklist
> for this particular STIG.

## Viewing the JSON Results

The JSON results file can optionally also be loaded into [heimdall-lite](https://heimdall-lite.mitre.org/) for an
interactive, graphical view of the InSpec results, if useful during review before generating the final `.ckl`.

## Source of Truth

- STIG benchmark content: [DISA Cyber Exchange / public.cyber.mil](https://public.cyber.mil/stigs/) —
  "Crunchy Data Postgres 16 Security Technical Implementation Guide", V1R3, 01 Jul 2026.
- Requirement text (titles, check/fix text, severity, CCI, SRG group, STIG IDs) retrieved programmatically from the
  published benchmark for accuracy; see `controls/*.rb` for the per-control source text.

## Contributing and Getting Help

To report a bug or feature request, please open an issue in this repository.
