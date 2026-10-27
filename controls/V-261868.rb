control 'V-261868' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish where the events occurred.'
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), check the current log_line_prefix setting by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_line_prefix"

    If log_line_prefix does not contain "%m %u %d %s", this is a finding.
  EOT
  desc 'fix', <<~EOT
    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Extra parameters can be added to the setting log_line_prefix to log application related information:

    # %a = application name
    # %u = user name
    # %d = database name
    # %r = remote host and port
    # %p = process ID
    # %m = timestamp with milliseconds
    # %i = command tag
    # %s = session startup
    # %e = SQL state

    For example:

    log_line_prefix = '< %m %a %u %d %r %p %i %e %s>'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000097-DB-000041'
  tag gid: 'V-261868'
  tag rid: 'SV-261868r1000609_rule'
  tag stig_id: 'CD16-00-001200'
  tag cci: ["CCI-000132"]
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
