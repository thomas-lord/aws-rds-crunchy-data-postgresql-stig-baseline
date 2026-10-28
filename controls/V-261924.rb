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

  unauthorized_superusers_sql = "SELECT rolname FROM pg_roles WHERE rolsuper = true;"
  # RDS always has at least one superuser (rdsadmin), so an empty result means the
  # query didn't actually run -- don't let `all` pass vacuously over an empty list.
  describe sql.query(unauthorized_superusers_sql, [conn.db]).lines do
    it { should_not be_empty }
    it { should all(be_in input('pg_superusers')) }
  end

  # On RDS the master user and anyone granted rds_superuser have nearly superuser powers
  # without the SUPERUSER flag, so the check above can't see them. Every role holding
  # rds_superuser, directly or through another role, must be the instance's master user
  # (created with the instance; RDS always makes it a member) or listed in
  # pg_rds_superusers. True superusers such as rdsadmin are covered above. The master
  # user's name comes from AWS (MasterUsername), not from pg_dba_user, so scanning as another
  # account can't approve that account by mistake; without AWS discovery this part is a
  # manual review.
  if conn.aws_available?
    rds_superusers_sql = "SELECT r.rolname FROM pg_roles r WHERE pg_has_role(r.oid, 'rds_superuser', 'MEMBER') AND NOT r.rolsuper AND r.rolname <> 'rds_superuser';"
    approved_rds_superusers = input('pg_rds_superusers') + [conn.aws_instance_attr('MasterUsername')].compact
    describe "Roles holding rds_superuser (approved: #{approved_rds_superusers.join(', ')})" do
      subject { sql.query(rds_superusers_sql, [conn.db]).lines }
      # The master user is always a member, so an empty result means the query didn't run.
      it { should_not be_empty }
      it { should all(be_in approved_rds_superusers) }
    end
  else
    manual_note = 'Without AWS CLI discovery (aws_db_instance_identifier + aws CLI) the instance\'s master user cannot be identified, so rds_superuser membership is not checked automatically. Manually confirm that every role holding rds_superuser (directly or through another role) is the master user or is approved by the organization.'
    describe manual_note do
      skip manual_note
    end
  end

  describe 'Manually review database/schema-level privileges (\\l and \\dn+ output) for unauthorized update ("W") or create ("C") grants; this portion cannot be fully automated without an organization-defined authorization matrix.' do
    skip 'Manually review database/schema-level privileges (\\l and \\dn+ output) for unauthorized update ("W") or create ("C") grants; this portion cannot be fully automated without an organization-defined authorization matrix.'
  end
end
