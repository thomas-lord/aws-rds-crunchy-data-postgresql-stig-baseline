control 'V-261943' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create a role "bob" and a test table by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE bob; CREATE TABLE test(id INT);"

    Set current role to "bob" and attempt to modify privileges:

    $ psql -c "SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;"

    As the database administrator (shown here as "postgres"), verify the unsuccessful attempt was logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    2024-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test
    2024-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob;

    If audit logs are not generated when unsuccessful attempts to add privileges/permissions occur, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to add privileges occur.

    All denials are logged by default if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag gid: 'V-261943'
  tag rid: 'SV-261943r1000834_rule'
  tag stig_id: 'CD16-00-009900'
  tag cci: ["CCI-000172"]
  tag nist: []
  conn = aws_rds_connection(
    aws_instance_id: input('aws_db_instance_identifier'),
    region: input('aws_region'),
    profile: input('aws_cli_profile'),
    host: input('pg_host'),
    port: input('pg_port'),
    db: input('pg_db'),
    dba: input('pg_dba')
  )
  sql = postgres_session(conn.dba, input('pg_dba_password'), conn.host, conn.port)

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  describe sql.query('SHOW pgaudit.log;', [conn.db]) do
    input('pgaudit_log_items').each do |item|
      its('output') { should match(/#{item}/) }
    end
  end

  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
