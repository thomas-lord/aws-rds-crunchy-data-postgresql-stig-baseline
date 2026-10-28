# aws-rds-crunchy-data-postgresql-stig-baseline

InSpec profile that checks an AWS RDS for PostgreSQL instance against the DISA
[Crunchy Data Postgres 16 STIG](https://public.cyber.mil/stigs/).

| | |
|---|---|
| STIG | Crunchy Data Postgres 16 (`CD_Postgres_16_STIG`), V1R3, 01 Jul 2026 |
| Controls | 111 |
| Target | AWS RDS for PostgreSQL 16 and later |
| Runner | Linux or macOS with InSpec (or [cinc-auditor](https://cinc.sh/start/auditor/)) |

For PostgreSQL 10–15, use a profile built on the older, deprecated Crunchy Data PostgreSQL STIG
(`CD_PostgreSQL_STIG`) instead; its control IDs and requirements differ.

## Quick start

```bash
cp inputs.yml.example inputs.yml   # fill in the instance ID, region and password
inspec exec . --input-file=inputs.yml --reporter=cli json:results.json
```

Then [convert the results to a `.ckl`](#producing-a-ckl-for-emass) for eMASS, or open `results.json` in
[Heimdall Lite](https://heimdall-lite.mitre.org/).

## Prerequisites

Install these on the runner host, which needs network access to the RDS instance:

| Tool | Needed for | Install |
|---|---|---|
| InSpec | Running the profile | `curl https://omnitruck.chef.io/install.sh \| sudo bash -s -- -P inspec`, or `gem install inspec-bin`, or use cinc-auditor |
| `psql` | All SQL checks | e.g. `sudo yum install postgresql` |
| AWS CLI | AWS checks and connection discovery (optional) | [AWS install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| `saf` CLI | Converting results to `.ckl` (optional) | `npm install -g @mitre/saf` |

The AWS credentials need read-only access to `rds:DescribeDBInstances`, `rds:DescribePendingMaintenanceActions`,
`ec2:DescribeSecurityGroups` and `cloudwatch:DescribeAlarmsForMetric`, plus `kms:DescribeKey` if you set
`pg_require_customer_managed_kms_key`.

## Inputs

Usually only these are needed:

```yaml
aws_db_instance_identifier: '<rds-db-instance-id>'   # the instance ID, not the endpoint
aws_region: 'us-east-1'
pg_dba_user: 'stig_audit'                            # the account the scan logs in as
pg_dba_password: '<password>'                        # always required; AWS can't return it
```

With the instance ID set, the profile looks up the host, port and database name from AWS. Without AWS access, set
`pg_host`, `pg_port` and `pg_db` yourself. The login account is never looked up: the scan always runs as
`pg_dba_user`.

To reach the database through a bastion host or SSH tunnel, set `pg_host` and `pg_port` to the tunnel's address and
`pg_use_manual_endpoint: true`. SQL then connects there, while everything else still comes from AWS.

### Audit account

Scan as a dedicated account rather than the master user. It needs only `pg_read_all_settings`, to read settings such
as `shared_preload_libraries`. Create it as the master user:

```sql
CREATE ROLE stig_audit LOGIN PASSWORD '<password>' CONNECTION LIMIT 2;
GRANT pg_read_all_settings TO stig_audit;
```

If the account lacks `pg_read_all_settings`, every SQL control fails with a message saying so, before any check runs.
The connection limit keeps the account from failing V-261857 itself. Don't grant it `rds_superuser`: V-261924 would
flag it.

Every other input has a STIG-aligned default. Change one only if your System Security Plan specifies a different
value. [inputs.yml.example](inputs.yml.example) lists them all, and [inspec.yml](inspec.yml) describes each one.

## How it works

Most controls run SQL against the database. Controls about settings that only AWS knows (encryption, security groups,
log export, alarms, maintenance, IAM auth) call the AWS CLI.

- **Failures are reported, never hidden.** Before any SQL control runs, the profile checks that it can connect. If it
  can't (wrong host, bad password, AWS lookup failed), every SQL control fails with that error, instead of
  passing on empty results. The check runs once per scan, so a bad password is tried only once.
- **AWS checks fail on AWS errors.** If the AWS CLI is missing or no instance ID is set, AWS-only controls are
  skipped. If AWS is configured but a call fails (expired credentials, missing permission, wrong region), they fail.
- **Pending parameter changes are flagged.** SQL controls report the live database value. If the instance's
  parameter group is `pending-reboot`, they also flag that the live value may not match the configured one.

### Control coverage

| Checked by | Controls |
|---|---|
| SQL: pgaudit loaded and logging the required classes | 29 |
| SQL: database settings, superusers, SSL, version | 26 |
| AWS CLI: security groups, log export, IAM auth, storage, alarms, maintenance | 8 |
| AWS CLI + SQL: encryption at rest | 3 |
| Manual review (needs organizational policy or documents) | 34 |
| Not applicable on RDS (AWS manages the OS and FIPS) | 11 |

Automated controls also flag any part they can't settle on their own for manual review, such as whether a CIDR is
approved in the PPSM CAL.

## Producing a `.ckl` for eMASS

```bash
saf convert hdf2ckl -i results.json -o results.ckl \
  --hostname <asset-hostname> --fqdn <asset-fqdn> --ip <asset-ip>
```

No blank checklist template is needed; the STIG metadata comes from the controls. For extra asset fields (role,
classification, etc.), generate a metadata file with `saf generate ckl_metadata -o metadata.json` and pass it with
`-m metadata.json`.

DISA publishes this STIG as manual-only (no SCAP content), so SCC can't scan it.

## Source of truth

- **Requirement text** (title, vulnerability discussion, check, fix, severity, CCI, SRG, STIG ID) is copied verbatim
  from the DISA V1R3 benchmark. Only how each check is automated is this profile's own work. The vulnerability
  discussion uses one-argument `desc`, not `desc 'default', ...`, because `inspec check` only recognizes that form.
- **NIST SP 800-53 tags** come from each control's CCI in the DISA CCI list (2025-01-23), using Revision 5. Four CCIs
  have no Rev 5 mapping (CCI-000196, CCI-001812, CCI-001814, CCI-001844); those controls use Rev 4 and are commented.
- The profile is standalone: it doesn't include controls from any other InSpec baseline.

## Contributing

Report bugs and feature requests by opening an issue in this repository.

CI runs on every pull request: RuboCop, `inspec check` (no errors or warnings allowed), and a scan of all 111
controls against a PostgreSQL 16 container that must finish with no control erroring out. Run `rubocop` locally
before opening a PR.
