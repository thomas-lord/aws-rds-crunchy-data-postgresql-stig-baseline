control 'V-261924' do
  title 'PostgreSQL must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc <<~EOT
    Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.

    When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

    Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.
  EOT
  desc 'check', <<~EOT
    To list all the permissions of individual roles, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    If any role has SUPERUSER that should not, this is a finding.

    List all the permissions of databases and schemas by running the following SQL:

    $ sudo su - postgres
    $ psql -c "\l"
    $ psql -c "\dn+"

    If any database or schema has update ("W") or create ("C") privileges and should not, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

    Use ALTER ROLE to remove accesses from roles:

    $ psql -c "ALTER ROLE <role_name> NOSUPERUSER"

    Use REVOKE to remove privileges from databases and schemas:

    $ psql -c "REVOKE ALL PRIVILEGES ON <table> FROM <role_name>"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag gid: 'V-261924'
  tag rid: 'SV-261924r1000777_rule'
  tag stig_id: 'CD16-00-007800'
  tag cci: ["CCI-001813"]
  tag nist: ["CM-5 (1) (a)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # RDS always has at least one superuser (rdsadmin), so an empty result means the query
  # didn't actually run -- an empty list must not pass.
  checks = [
    rds_check("Superusers (approved: #{input('pg_superusers').join(', ')})") do
      rows = sql.query('SELECT rolname FROM pg_roles WHERE rolsuper = true;', [conn.db]).lines
      [!rows.empty? && (rows - input('pg_superusers')).empty?, rows.empty? ? 'none (query did not run)' : rows.join(', ')]
    end
  ]
  manual_note = 'Manually review database and schema privileges (\\l and \\dn+ output) for unauthorized update ("W") or create ("C") grants; this needs an organization-defined authorization matrix.'

  # On RDS the master user and anyone granted rds_superuser have nearly superuser powers
  # without the SUPERUSER flag, so the check above can't see them. Every role holding
  # rds_superuser, directly or through another role, must be the instance's master user
  # (created with the instance; RDS always makes it a member) or listed in
  # pg_rds_superusers. The master user's name comes from AWS (MasterUsername), not from
  # pg_dba_user, so scanning as another account can't approve that account by mistake;
  # without AWS discovery this part is a manual review.
  if conn.aws_available?
    approved_rds_superusers = input('pg_rds_superusers') + [conn.aws_instance_attr('MasterUsername')].compact
    checks << rds_check("Roles holding rds_superuser (approved: #{approved_rds_superusers.join(', ')})") do
      rows = sql.query("SELECT r.rolname FROM pg_roles r WHERE pg_has_role(r.oid, 'rds_superuser', 'MEMBER') AND NOT r.rolsuper AND r.rolname <> 'rds_superuser';", [conn.db]).lines
      # The master user is always a member, so an empty result means the query didn't run.
      [!rows.empty? && (rows - approved_rds_superusers).empty?, rows.empty? ? 'none (query did not run)' : rows.join(', ')]
    end
  else
    manual_note += ' Without AWS CLI discovery the master user cannot be identified, so also confirm that every role holding rds_superuser (directly or through another role) is the master user or approved by the organization.'
  end
  rds_review_results(checks, manual_note).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
