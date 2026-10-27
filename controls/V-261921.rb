control 'V-261921' do
  title 'PostgreSQL must record time stamps in audit records and application data that can be mapped to Coordinated Universal Time (UTC), formerly Greenwich Mean Time (GMT).'
  desc 'check', <<~EOT
    When a PostgreSQL cluster is initialized using initdb, the PostgreSQL cluster will be configured to use the same time zone as the target server.

    As the database administrator (shown here as "postgres"), check the current log_timezone setting by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_timezone"

    log_timezone
    --------------
    UTC
    (1 row)

    If log_timezone is not set to the desired time zone, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To change log_timezone in postgresql.conf to use a different time zone for logs, as the database administrator (shown here as "postgres"), run the following:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    log_timezone='UTC'

    Restart the database:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000374-DB-000322'
  tag gid: 'V-261921'
  tag rid: 'SV-261921r1000994_rule'
  tag stig_id: 'CD16-00-007500'
  tag cci: ["CCI-001890"]
  tag nist: []
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW log_timezone;', [input('pg_db')]) do
    its('output.strip') { should cmp input('pg_timezone') }
  end
end
