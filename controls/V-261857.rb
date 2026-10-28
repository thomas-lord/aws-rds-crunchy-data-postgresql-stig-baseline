control 'V-261857' do
  title 'PostgreSQL must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc <<~EOT
    Database management includes the ability to control the number of users and user sessions using PostgreSQL. Unlimited concurrent connections to PostgreSQL could allow a successful denial-of-service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

    This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

    The capability to limit the number of concurrent sessions per user must be configured in or added to PostgreSQL (for example, by use of a log on trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to PostgreSQL by other means.

    The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, two might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

    (Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms).
  EOT
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

  # Per-role limits (rolconnlimit) for every role that can log in; a limit means nothing
  # for NOLOGIN roles. -1 means unlimited, which the STIG always counts as a finding.
  # Roles in pg_connection_limit_exempt_roles are skipped (by default rdsadmin, AWS's own
  # account, whose limit customers can't change).
  max_per_role = input('pg_max_connections_per_role').to_i
  exempt_roles = input('pg_connection_limit_exempt_roles')
  role_rows = sql.query('SELECT rolname, rolconnlimit FROM pg_roles WHERE rolcanlogin ORDER BY rolname;', [conn.db]).lines
  # Each row is "name|limit"; anything else (e.g. an error message) is reported as unreadable.
  unreadable_rows = role_rows.grep_v(/\A[^|]+\|-?\d+\z/)
  role_limits = (role_rows - unreadable_rows).to_h { |row| [row.split('|')[0], row.split('|')[1].to_i] }
  over_limit = role_limits.except(*exempt_roles)
                          .select { |_, limit| limit == -1 || limit > max_per_role }
                          .map { |name, limit| "#{name} (#{limit == -1 ? 'unlimited' : limit})" }
  describe "Login role connection limits (max #{max_per_role} per role; exempt: #{exempt_roles.empty? ? 'none' : exempt_roles.join(', ')})" do
    # The scanning account can log in, so an empty list means the query didn't run.
    it 'should list at least one login role' do
      expect(role_limits).not_to be_empty
    end
    it 'should return only role/limit rows' do
      expect(unreadable_rows).to be_empty
    end
    it 'should have no role unlimited (-1) or above the per-role maximum' do
      expect(over_limit).to be_empty
    end
  end

  rds_check_parameter_apply_status(conn)
end
