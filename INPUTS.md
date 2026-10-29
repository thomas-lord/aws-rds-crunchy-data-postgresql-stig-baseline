# Inputs

Inputs tell the profile how to reach the database and what your organization has approved. Set them in an inputs
file and pass it with `--input-file inputs.yml`. [inputs.yml.example](inputs.yml.example) is a starting point, and
[inspec.yml](inspec.yml) holds the defaults.

Only the connection inputs are required. Every other input has a STIG-aligned default, so change one only when your
System Security Plan (SSP) says something different.

- [Connection](#connection)
- [Expected settings](#expected-settings)
- [Organization limits and policy](#organization-limits-and-policy)
- [Approval lists](#approval-lists)
- [IAM check for audit settings](#iam-check-for-audit-settings)
- [Example](#example)

## Connection

| Input | Default | What it does |
|---|---|---|
| `aws_db_instance_identifier` | `""` | The RDS instance identifier (not the endpoint). When set, and the AWS CLI works, the host, port and database name come from AWS, and the AWS checks run. |
| `aws_region` | `""` | The instance's region, passed to the AWS CLI. |
| `aws_cli_profile` | `""` | A named AWS CLI profile. Blank uses the default credential chain. |
| `pg_dba_user` | none, required | The account the scan logs in as. Never looked up from AWS. See [Audit account](README.md#audit-account). |
| `pg_dba_password` | `""`, required | Its password. Marked sensitive, so it never appears in reports. |
| `pg_host` | `localhost` | Fallback host when AWS discovery isn't used. Marked sensitive. |
| `pg_port` | `5432` | Fallback port. |
| `pg_db` | `postgres` | Fallback database name. |
| `pg_use_manual_endpoint` | `false` | `true` connects SQL to `pg_host`/`pg_port` even with AWS discovery on, e.g. through a bastion or SSH tunnel. The AWS checks still use discovery. |

## Expected settings

Each value is what the STIG requires, and the scan compares the live database setting to it.

| Input | Default | Controls |
|---|---|---|
| `pg_log_line_prefix` | `%m:%r:%u@%d:[%p]:%l:%e:%s:%v:%x:%c:%q%a:` | V-261866, 867, 868, 869, 871, 922, 961 |
| `pg_log_connections` | `on` | V-261866, 956, 957, 960, 961 |
| `pg_log_disconnections` | `on` | V-261866, 957, 960, 961 |
| `pg_log_hostname` | `on` | V-261869 |
| `pg_timezone` | `UTC` | V-261921 (`log_timezone`) |
| `pg_ssl` | `on` | V-261900, 928, 932, 933 |
| `pg_password_encryption` | `scram-sha-256` | V-261891, 892 |
| `pg_client_min_messages` | `error` | V-261908, 909 |
| `pgaudit_log_items` | `[ddl, role, read, write]` | The pgaudit controls (V-261860, 861, 863, 864, 865, 870, 938 to 955, 958, 959, 962, 963, 964). Accepts pgaudit syntax, e.g. `[all, -misc]`. |

RDS allows only two values for `log_line_prefix`. The default is the one that includes the millisecond timestamp
(`%m`) and application name (`%a`) the STIG requires.

## Organization limits and policy

| Input | Default | What it does |
|---|---|---|
| `pg_max_connections` | `100` | Highest allowed `max_connections` (V-261857). |
| `pg_max_connections_per_role` | `100` | Highest allowed `CONNECTION LIMIT` for each login role (V-261857). A role with no limit (`-1`) is always a finding. |
| `pg_connection_limit_exempt_roles` | `[rdsadmin]` | Login roles skipped by the per-role limit check (V-261857). `rdsadmin` is AWS's own account. |
| `pg_storage_alarm_threshold_percent` | `75` | Percent of storage used by which a CloudWatch alarm must warn support staff (V-261919). |
| `pg_encryption_of_data_at_rest_required` | `true` | Whether the AO requires encryption at rest (V-261901, 930, 931). |
| `pg_require_customer_managed_kms_key` | `false` | `true` also requires a customer-managed KMS key rather than `aws/rds` (V-261901, 930, 931). The STIG doesn't require it. Needs `kms:DescribeKey`. |
| `pg_require_session_timeouts` | `false` | `true` fails V-261910 when `idle_session_timeout` or `idle_in_transaction_session_timeout` is 0. `false` lists their values for manual review. |
| `pg_public_access_approved` | `false` | `true` accepts a publicly accessible instance as a documented exception (V-261889, 926). |

## Approval lists

These inputs record what your organization has documented and approved. Anything the scan finds that isn't listed is
a finding, and the result names it, so the fix is either to remove it from the database or to approve it and add it
here. Most default to empty, so a new system fails these controls until its approvals are filled in.

Checks marked "every database" run in each database that accepts connections, except `rdsadmin`. The scan account
needs `CONNECT` on each one.

| Input | Default | Controls | Lists |
|---|---|---|---|
| `pg_approved_password_roles` | `[]` | V-261858 | Login roles that authenticate by password instead of IAM (`rds_iam`) or Kerberos (`rds_ad`). Usually the master user, the audit account and application accounts. |
| `pg_approved_admin_roles` | `[]` | V-261859 | Roles allowed to hold `SUPERUSER`, `CREATEROLE`, `CREATEDB`, `BYPASSRLS` or `REPLICATION`. On RDS the master user has `CREATEROLE` and `CREATEDB`, so list it. |
| `pg_approved_object_privileges` | `{}` | V-261859 | For each role, the privileges it may hold on tables, views, sequences and their columns that it doesn't own, every database. Use `PUBLIC` for grants to everyone. |
| `pg_superusers` | `[rdsadmin]` | V-261862, 924 | Roles with `SUPERUSER`. On RDS only AWS's `rdsadmin` has it. |
| `pg_rds_superusers` | `[]` | V-261924 | Roles holding `rds_superuser`, directly or through another role, besides the master user, which is always allowed. Needs AWS discovery. |
| `pg_approved_extensions` | `[pgaudit]` | V-261886 | Extensions installed in any database, every database. `plpgsql` is always allowed. |
| `pg_approved_procedural_languages` | `[]` | V-261915 | Procedural languages besides `plpgsql`, every database. |
| `pg_approved_security_definer_functions` | `[]` | V-261916 | `SECURITY DEFINER` functions, as `schema.function`, every database. Functions in system schemas or extensions aren't checked. |
| `pg_approved_schema_creators` | `[]` | V-261923 | Roles besides the owner that hold `CREATE` on a schema or database, every database. `PUBLIC` is a finding unless listed. |
| `pg_approved_ingress_cidrs` | `[]` | V-261889, 926 | CIDR blocks and prefix-list IDs approved (PPSM CAL) to reach the database port through the security groups. `0.0.0.0/0` and `::/0` are always a finding. |

`pg_approved_object_privileges` takes a role name followed by its privileges. Privilege names aren't case-sensitive,
and a privilege approved for a role also covers grants on single columns:

```yaml
pg_approved_object_privileges:
  app_user: [SELECT, INSERT, UPDATE, DELETE, USAGE]   # USAGE for its sequences
  stig_audit: [SELECT]
```

## IAM check for audit settings

| Input | Default | Controls |
|---|---|---|
| `pg_audit_config_denied_principals` | `[]` | V-261862 |

V-261862 requires that only personnel appointed by the ISSM can choose which events are audited. On RDS those
settings live in the DB parameter group, so who can change them is an IAM question.

List the ARNs of one or more IAM roles or users that the ISSM has **not** appointed. The scan simulates each one with
`iam simulate-principal-policy` against `rds:ModifyDBParameterGroup` and `rds:ResetDBParameterGroup` on the
instance's parameter group, and `rds:ModifyDBInstance` on the instance. Every action must be denied. The result lists
each decision, which serves as the evidence.

Left empty, V-261862 reports **Not Reviewed** with instructions for checking by hand. Setting it needs the extra
permission `iam:SimulatePrincipalPolicy`.

```yaml
pg_audit_config_denied_principals:
  - arn:aws:iam::111122223333:role/app-developers
```

## Example

A system with a master user, an audit account and one application account, using password authentication:

```yaml
aws_db_instance_identifier: 'orders-db'
aws_region: 'us-east-1'
pg_dba_user: 'stig_audit'
pg_dba_password: '<password>'

pg_approved_password_roles: [db_admin, stig_audit, orders_app]
pg_approved_admin_roles: [db_admin]
pg_approved_object_privileges:
  orders_app: [SELECT, INSERT, UPDATE, DELETE, USAGE]
pg_approved_ingress_cidrs: ['10.20.0.0/16']
pg_audit_config_denied_principals:
  - arn:aws:iam::111122223333:role/app-developers
```

Keep the real inputs file out of version control: it holds the password, and its approval lists describe the system.
