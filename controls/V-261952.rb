control 'V-261952' do
  title 'PostgreSQL must generate audit records when security objects are deleted.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create a test table stig_test, enable row level security, and create a policy by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE TABLE stig_test(id INT)"
    $ psql -c "ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY"
    $ psql -c "CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user)"

    Drop the policy and disable row level security:

    $ psql -c "DROP POLICY lock_table ON stig_test"
    $ psql -c "ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY"

    As the database administrator (shown here as "postgres"), verify the security objects deletions were logged:

    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    2024-03-30 14:54:18.991 UTC postgres postgres LOG: AUDIT: SESSION,11,1,DDL,DROP POLICY,,,DROP POLICY lock_table ON stig_test;,<none>
    2024-03-30 14:54:42.373 UTC postgres postgres LOG: AUDIT: SESSION,12,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY;,<none>

    If audit records are not produced when security objects are dropped, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log = 'ddl'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag gid: 'V-261952'
  tag rid: 'SV-261952r1000861_rule'
  tag stig_id: 'CD16-00-010800'
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
