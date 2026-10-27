control 'V-261922' do
  title 'PostgreSQL must generate time stamps for audit records and application data with a minimum granularity of one second.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), verify the current log_line_prefix setting by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_line_prefix"

    If log_line_prefix does not contain %m, this is a finding.

    Check the logs to verify time stamps are being logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    < 2024-02-23 12:53:33.947 EDT postgres postgres 570bd68d.3912 >LOG: connection authorized: user=postgres database=postgres
    < 2024-02-23 12:53:41.576 EDT postgres postgres 570bd68d.3912 >LOG: AUDIT: SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE test_srg(id INT);,<none>
    < 2024-02-23 12:53:44.372 EDT postgres postgres 570bd68d.3912 >LOG: disconnection: session time: 0:00:10.426 user=postgres database=postgres host=[local]

    If time stamps are not being logged, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL will not log anything if logging is not enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    If logging is enabled, the following configurations must be made to log events with time stamps:

    As the database administrator (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add %m to log_line_prefix to enable time stamps with milliseconds:

    log_line_prefix = '< %m >'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000375-DB-000323'
  tag gid: 'V-261922'
  tag rid: 'SV-261922r1000771_rule'
  tag stig_id: 'CD16-00-007600'
  tag cci: ["CCI-001889"]
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
