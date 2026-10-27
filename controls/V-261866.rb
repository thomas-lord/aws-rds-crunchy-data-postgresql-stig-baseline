control 'V-261866' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish what type of events occurred.'
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), verify the current log_line_prefix setting:

    $ sudo su - postgres
    $ psql -c "SHOW log_line_prefix"

    Verify that the current settings are appropriate for the organization.

    The following is what is possible for logged information:

    # %a = application name
    # %u = user name
    # %d = database name
    # %r = remote host and port
    # %h = remote host
    # %p = process ID
    # %t = timestamp without milliseconds
    # %m = timestamp with milliseconds
    # %i = command tag
    # %e = SQL state
    # %c = session ID
    # %l = session line number
    # %s = session start timestamp
    # %v = virtual transaction ID
    # %x = transaction ID (0 if none)
    # %q = stop here in non-session processes

    If the audit record does not log events required by the organization, this is a finding.

    Verify the current settings of log_connections and log_disconnections by running the following SQL:

    $ psql -c "SHOW log_connections"
    $ psql -c "SHOW log_disconnections"

    If either setting is off, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C. 

    If logging is enabled the following configurations must be made to log connections, date/time, username and session identifier.

    Edit the postgresql.conf file as a privileged user:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Edit the following parameters based on the organization's needs (minimum requirements are as follows):

    log_connections = on
    log_disconnections = on
    log_line_prefix = '< %m %u %d %c: >'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag gid: 'V-261866'
  tag rid: 'SV-261866r1000603_rule'
  tag stig_id: 'CD16-00-001000'
  tag cci: ["CCI-000130"]
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

  describe sql.query('SHOW log_connections;', [conn.db]) do
    its('output.strip') { should cmp input('pg_log_connections') }
  end

  describe sql.query('SHOW log_disconnections;', [conn.db]) do
    its('output.strip') { should cmp input('pg_log_disconnections') }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
