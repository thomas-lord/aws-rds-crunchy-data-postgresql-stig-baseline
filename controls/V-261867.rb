control 'V-261867' do
  title 'PostgreSQL must produce audit records containing time stamps to establish when the events occurred.'
  desc 'check', <<~EOT
    As the database administrator (usually postgres), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_line_prefix"

    If the query result does not contain "%m", this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Logging must be enabled to capture timestamps. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    If logging is enabled, the following configurations must be made to log events with timestamps:

    As the database administrator (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add %m to log_line_prefix to enable timestamps with milliseconds:

    log_line_prefix = '< %m >'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000096-DB-000040'
  tag gid: 'V-261867'
  tag rid: 'SV-261867r1000955_rule'
  tag stig_id: 'CD16-00-001100'
  tag cci: ["CCI-000131"]
  tag nist: ["AU-3 b"]
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

  describe sql.query('SHOW log_line_prefix;', [conn.db]) do
    its('output.strip') { should cmp input('pg_log_line_prefix') }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
