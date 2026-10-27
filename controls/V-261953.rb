control 'V-261953' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to delete security objects occur.'
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

    Configure PostgreSQL to produce audit records when unsuccessful attempts to delete security objects occur.

    All errors and denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    With pgaudit installed the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log='ddl, role, read, write'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag gid: 'V-261953'
  tag rid: 'SV-261953r1000864_rule'
  tag stig_id: 'CD16-00-010900'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
  conn = aws_rds_connection(
    aws_instance_id: input('aws_db_instance_identifier'),
    region: input('aws_region'),
    profile: input('aws_cli_profile'),
    host: input('pg_host'),
    port: input('pg_port'),
    db: input('pg_db'),
    dba: input('pg_dba')
  )
  sql = conn.sql_session(input('pg_dba_password'))

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
