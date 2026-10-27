control 'V-261963' do
  title 'PostgreSQL must generate audit records when unsuccessful accesses to objects occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create a schema, test_schema, create a table, test_table, within test_schema, and insert a value:

    $ sudo su - postgres
    $ psql -c "CREATE SCHEMA test_schema"
    $ psql -c "CREATE TABLE test_schema.test_table(id INT)"
    $ psql -c "INSERT INTO test_schema.test_table(id) VALUES (0)"

    Create a role "bob" and attempt to SELECT, INSERT, UPDATE, and DROP from the test table: 

    $ psql -c "CREATE ROLE BOB"
    $ psql -c "SET ROLE bob; SELECT * FROM test_schema.test_table"

    $ psql -c "SET ROLE bob; INSERT INTO test_schema.test_table VALUES (0)"
    $ psql -c "SET ROLE bob; UPDATE test_schema.test_table SET id = 1 WHERE id = 0"
    $ psql -c "SET ROLE bob; DROP TABLE test_schema.test_table"
    $ psql -c "SET ROLE bob; DROP SCHEMA test_schema"

    As the database administrator (shown here as "postgres"), review PostgreSQL/database security and audit settings to verify that audit records are created for unsuccessful attempts at the specified access to the specified objects:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    2024-03-30 17:23:41.254 EDT postgres postgres ERROR: permission denied for schema test_schema at character 15
    2024-03-30 17:23:41.254 EDT postgres postgres STATEMENT: SELECT * FROM test_schema.test_table;
    2024-03-30 17:23:53.973 EDT postgres postgres ERROR: permission denied for schema test_schema at character 13
    2024-03-30 17:23:53.973 EDT postgres postgres STATEMENT: INSERT INTO test_schema.test_table VALUES (0);
    2024-03-30 17:24:32.647 EDT postgres postgres ERROR: permission denied for schema test_schema at character 8
    2024-03-30 17:24:32.647 EDT postgres postgres STATEMENT: UPDATE test_schema.test_table SET id = 1 WHERE id = 0;
    2024-03-30 17:24:46.197 EDT postgres postgres ERROR: permission denied for schema test_schema
    2024-03-30 17:24:46.197 EDT postgres postgres STATEMENT: DROP TABLE test_schema.test_table;
    2024-03-30 17:24:51.582 EDT postgres postgres ERROR: must be owner of schema test_schema
    2024-03-30 17:24:51.582 EDT postgres postgres STATEMENT: DROP SCHEMA test_schema;

    If any of the above steps did not create audit records for SELECT, INSERT, UPDATE, and DROP, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to access objects occur.

    All errors and denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag gid: 'V-261963'
  tag rid: 'SV-261963r1000894_rule'
  tag stig_id: 'CD16-00-011900'
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
