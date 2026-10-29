control 'V-261862' do
  title 'PostgreSQL must allow only the information system security manager (ISSM), or individuals or roles appointed by the ISSM, to select which events are to be audited.'
  desc <<~EOT
    Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

    Suppression of auditing could permit an adversary to evade detection.

    Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Check PostgreSQL settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.

    As the database administrator (shown here as "postgres"), verify the permissions for PGDATA:

    $ ls -la ${PGDATA?}

    If anything in PGDATA is not owned by the database administrator, this is a finding.

    As the database administrator, run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    Review the role permissions, if any role is listed as superuser but should not have that access, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL's settings to allow designated personnel to select which auditable events are audited.

    Using pgaudit allows administrators the flexibility to choose what they log. For an overview of the capabilities of pgaudit, refer to https://github.com/pgaudit/pgaudit. 

    Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    Refer to supplementary content APPENDIX-C for instructions on enabling logging. Only administrators/superuser can change PostgreSQL configurations. Access to the database administrator must be limited to designated personnel only.

    To ensure that postgresql.conf is owned by the database owner:

    $ chown postgres:postgres ${PGDATA?}/postgresql.conf
    $ chmod 600 ${PGDATA?}/postgresql.conf
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag gid: 'V-261862'
  tag rid: 'SV-261862r1000591_rule'
  tag stig_id: 'CD16-00-000600'
  tag cci: ["CCI-000171"]
  tag nist: ["AU-12 b"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # PGDATA ownership is inherited from AWS: customers have no file system access on RDS.
  # Which events are audited is set in the instance's DB parameter group, so who can change it
  # is an IAM question. Each role or user ARN in pg_audit_config_denied_principals (accounts not
  # appointed by the ISSM) is simulated against the actions that change it, and must be denied.
  # RDS always has a superuser (rdsadmin), so an empty superuser list means the query didn't run.
  checks = [
    rds_check("Superusers (approved: #{input('pg_superusers').join(', ')})") do
      rows = sql.query('SELECT rolname FROM pg_roles WHERE rolsuper = true;', [conn.db]).lines
      [!rows.empty? && (rows - input('pg_superusers')).empty?, rows.empty? ? 'none (query did not run)' : rows.join(', ')]
    end
  ]
  principals = input('pg_audit_config_denied_principals')
  manual_note = nil
  if principals.empty? || !conn.aws_available?
    manual_note = 'Manually verify that only personnel appointed by the ISSM can change the DB parameter group (pgaudit and logging parameters) or the instance (rds:ModifyDBParameterGroup, rds:ResetDBParameterGroup, rds:ModifyDBInstance), ' \
                  'e.g. with aws iam simulate-principal-policy for a non-appointed role. List such roles or users in pg_audit_config_denied_principals to check this automatically.'
  else
    checks << rds_check('IAM roles and users not appointed by the ISSM (pg_audit_config_denied_principals) denied changing audit settings') do
      results = principals.map { |arn| [arn, conn.audit_config_decisions(arn)] }
      allowed = results.flat_map { |arn, decisions| decisions.select { |_, decision| decision == 'allowed' }.map { |action, _| "#{arn} #{action}" } }
      found = results.map { |arn, decisions| "#{arn}: #{decisions.map { |action, decision| "#{action.delete_prefix('rds:')} #{decision}" }.join(', ')}" }
      [allowed.empty?, allowed.empty? ? found.join('; ') : "allowed: #{allowed.join(', ')}"]
    end
  end
  rds_review_results(checks, manual_note).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
