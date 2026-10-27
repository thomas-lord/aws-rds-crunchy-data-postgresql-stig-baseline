control 'V-261899' do
  title 'PostgreSQL must invalidate session identifiers upon user logout or other session termination.'
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -h localhost -c "SHOW tcp_keepalives_idle"
    $ psql -h localhost -c "SHOW tcp_keepalives_interval"
    $ psql -h localhost -c "SHOW tcp_keepalives_count"
    $ psql -h localhost -c "SHOW statement_timeout"

    If these settings are not set to something other than zero, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    As the database administrator (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi $PGDATA/postgresql.conf

    Set the following parameters to organizational requirements:

    statement_timeout = 10000 #milliseconds
    tcp_keepalives_idle = 10 # seconds
    tcp_keepalives_interval = 10 # seconds
    tcp_keepalives_count = 10

    As the system administrator, restart the server with the new configuration:

    $ sudo systemctl restart postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000220-DB-000149'
  tag gid: 'V-261899'
  tag rid: 'SV-261899r1043179_rule'
  tag stig_id: 'CD16-00-004700'
  tag cci: ["CCI-001185"]
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

  describe sql.query('SHOW tcp_keepalives_idle;', [conn.db]) do
    its('output.strip') { should match(/\A[1-9]\d*(us|ms|s|min|h|d)?\z/) }
  end

  describe sql.query('SHOW tcp_keepalives_interval;', [conn.db]) do
    its('output.strip') { should match(/\A[1-9]\d*(us|ms|s|min|h|d)?\z/) }
  end

  describe sql.query('SHOW tcp_keepalives_count;', [conn.db]) do
    its('output.strip') { should match(/\A[1-9]\d*(us|ms|s|min|h|d)?\z/) }
  end

  describe sql.query('SHOW statement_timeout;', [conn.db]) do
    its('output.strip') { should match(/\A[1-9]\d*(us|ms|s|min|h|d)?\z/) }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
