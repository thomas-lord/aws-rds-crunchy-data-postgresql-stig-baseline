control 'V-261869' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish the sources (origins) of the events.'
  desc 'check', <<~EOT
    Check PostgreSQL settings and existing audit records to verify information specific to the source (origin) of the event is being captured and stored with audit records.

    As the database administrator (usually postgres) check the current log_line_prefix and log_hostname setting by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_line_prefix"
    $ psql -c "SHOW log_hostname"

    For a complete list of extra information that can be added to log_line_prefix, refer to the official documentation: https://www.postgresql.org/docs/current/static/runtime-config-logging.html#GUC-LOG-LINE-PREFIX.

    If the current settings do not provide enough information regarding the source of the event, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

    If logging is enabled, the following configurations can be made to log the source of an event.

    As the database administrator, edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    ###### Log Line Prefix

    Extra parameters can be added to the setting log_line_prefix to log source of event:

    # %a = application name
    # %u = user name
    # %d = database name
    # %r = remote host and port
    # %p = process ID
    # %m = timestamp with milliseconds

    For example:
    log_line_prefix = '< %m %a %u %d %r %p %m >'

    ###### Log Hostname

    By default, only IP address is logged. To also log the hostname, the following parameter can also be set in postgresql.conf:

    log_hostname = on

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000098-DB-000042'
  tag gid: 'V-261869'
  tag rid: 'SV-261869r1000956_rule'
  tag stig_id: 'CD16-00-001300'
  tag cci: ["CCI-000133"]
  tag nist: ["AU-3 d"]
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

  describe sql.query('SHOW log_hostname;', [conn.db]) do
    its('output.strip') { should cmp input('pg_log_hostname') }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
