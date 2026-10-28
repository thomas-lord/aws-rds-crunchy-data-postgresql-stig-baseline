control 'V-261938' do
  title 'PostgreSQL must be able to generate audit records when security objects are accessed.'
  desc <<~EOT
    Changes to the security configuration must be tracked.

    This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

    In an SQL environment, types of access include, but are not necessarily limited to:
    SELECT
    INSERT
    UPDATE
    DELETE
    EXECUTE
  EOT
  desc 'check', <<~EOT
    As the database administrator, verify pgaudit is enabled by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW shared_preload_libraries"

    If the output does not contain pgaudit, this is a finding.

    Verify that role, read, write, and ddl auditing are enabled:

    $ psql -c "SHOW pgaudit.log"

    If the output does not contain role, read, write, and ddl, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL can be configured to audit these requests using pgaudit.. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed, the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log='ddl, role, read, write'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag gid: 'V-261938'
  tag rid: 'SV-261938r1000819_rule'
  tag stig_id: 'CD16-00-009400'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  rds_check_pgaudit_log(conn, sql)

  rds_check_parameter_apply_status(conn)
end
