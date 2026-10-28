control 'V-261946' do
  title 'PostgreSQL must generate audit records when security objects are modified.'
  desc <<~EOT
    Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.
  EOT
  desc 'check', <<~EOT
    As the database administrator, verify pgaudit is enabled by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW shared_preload_libraries"

    If the results does not contain pgaudit, this is a finding.

    Verify that role, read, write, and ddl auditing are enabled:

    $ psql -c "SHOW pgaudit.log"

    If the output does not contain role, read, write, and ddl, this is a finding.

    Verify that accessing the catalog is audited by running the following SQL:

    $ psql -c "SHOW pgaudit.log_catalog"

    If log_catalog is not on, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed, the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log_catalog = 'on'
    pgaudit.log='ddl, role, read, write'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag gid: 'V-261946'
  tag rid: 'SV-261946r1000843_rule'
  tag stig_id: 'CD16-00-010200'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  rds_check_pgaudit_log(conn, sql)

  describe sql.query('SHOW pgaudit.log_catalog;', [conn.db]) do
    its('output.strip') { should cmp 'on' }
  end

  rds_check_parameter_apply_status(conn)
end
