control 'V-261951' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to delete privileges/permissions occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create the roles "joe" and "bob" with LOGIN by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE joe LOGIN"
    $ psql -c "CREATE ROLE bob LOGIN"

    Set current role to "bob" and attempt to alter the role "joe":

    $ psql -c "SET ROLE bob; ALTER ROLE joe NOLOGIN;"

    As the database administrator (shown here as "postgres"), verify the denials are logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    < 2024-03-17 11:28:10.004 UTC bob 56eacd05.cda postgres: >ERROR: permission denied to alter role
    < 2024-03-17 11:28:10.004 UTC bob 56eacd05.cda postgres: >STATEMENT: ALTER ROLE joe;

    If audit logs are not generated when unsuccessful attempts to delete privileges/permissions occur, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to delete privileges occur.

    All denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag gid: 'V-261951'
  tag rid: 'SV-261951r1000858_rule'
  tag stig_id: 'CD16-00-010700'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  describe sql.query('SHOW pgaudit.log;', [conn.db]) do
    input('pgaudit_log_items').each do |item|
      its('output') { should match(/#{item}/) }
    end
  end

  rds_check_parameter_apply_status(conn)
end
