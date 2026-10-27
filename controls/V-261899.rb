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
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW tcp_keepalives_idle;', [input('pg_db')]) do
    its('output.strip') { should_not cmp '0' }
  end

  describe sql.query('SHOW tcp_keepalives_interval;', [input('pg_db')]) do
    its('output.strip') { should_not cmp '0' }
  end

  describe sql.query('SHOW tcp_keepalives_count;', [input('pg_db')]) do
    its('output.strip') { should_not cmp '0' }
  end

  describe sql.query('SHOW statement_timeout;', [input('pg_db')]) do
    its('output.strip') { should_not cmp '0' }
  end
end
