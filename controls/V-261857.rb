control 'V-261857' do
  title 'PostgreSQL must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'check', <<~EOT
    To check the total amount of connections allowed by the database, as the database administrator, run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW max_connections"

    If the total amount of connections is greater than documented by an organization, this is a finding.

    To check the amount of connections allowed for each role, as the database administrator, run the following SQL:

    $ sudo su - postgres
    $ psql -c "SELECT rolname, rolconnlimit 
    FROM pg_roles
    WHERE rolname NOT IN (
    'pg_database_owner',
    'pg_read_all_data',
    'pg_write_all_data',
    'pg_monitor',
    'pg_read_all_settings',
    'pg_read_all_stats',
    'pg_stat_scan_tables',
    'pg_read_server_files',
    'pg_write_server_files',
    'pg_execute_server_program',
    'pg_signal_backend',
    'pg_checkpoint',
    'pg_use_reserved_connections',
    'pg_create_subscription');"

    If any roles have more connections configured than documented, this is a finding. A value of "-1" indicates Unlimited and is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To configure the maximum amount of connections allowed to the database, as the database administrator (shown here as "postgres") change the following in postgresql.conf (the value 10 is an example; set the value to suit local conditions):

    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 
    max_connections = 10 

    Restart the database:

    $ sudo systemctl restart postgresql-${PGVER?}

    To limit the amount of connections allowed by a specific role, as the database administrator, run the following SQL: 

    $ psql -c "ALTER ROLE <rolname> CONNECTION LIMIT 1";
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-261857'
  tag rid: 'SV-261857r1000976_rule'
  tag stig_id: 'CD16-00-000100'
  tag cci: ["CCI-000054"]
  tag nist: ["AC-10"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # Assert the value is numeric before comparing: non-numeric output (e.g. an
  # error message) would otherwise coerce to 0 via to_i and pass the <= check.
  describe 'SHOW max_connections' do
    subject { sql.query('SHOW max_connections;', [conn.db]).output.strip }
    it { should match(/\A\d+\z/) }
    it { should cmp <= input('pg_max_connections').to_i }
  end

  rds_check_parameter_apply_status(conn)
end
