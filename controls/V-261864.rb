control 'V-261864' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc <<~EOT
    Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. PostgreSQLs typically make such information available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to determine if any and every action on the database is permitted.

    To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variables. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG.

    As the database administrator (shown here as "postgres"), create a role "bob" by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE bob"

    Attempt to retrieve information from the pg_authid table:

    $ psql -c "SET ROLE bob; SELECT * FROM pg_authid"
    $ psql -c "DROP ROLE bob;"

    As the database administrator (shown here as "postgres"), verify the event was logged in PGLOG:

    $ sudo su - postgres
    $ cat ${PGLOG?}/<latest_log>
    < 2024-02-13 16:49:58.864 UTC postgres postgres ERROR: > permission denied for relation pg_authid
    < 2024-02-13 16:49:58.864 UTC postgres postgres STATEMENT: > SELECT * FROM pg_authid

    If the above steps cannot verify that audit records are produced when PostgreSQL denies retrieval of privileges/permissions/role memberships, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges occur.

    All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag gid: 'V-261864'
  tag rid: 'SV-261864r1000597_rule'
  tag stig_id: 'CD16-00-000800'
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
