control 'V-261871' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.'
  desc 'check', <<~EOT
    Check PostgreSQL settings and existing audit records to verify a username associated with the event is being captured and stored with the audit records. If audit records exist without specific user information, this is a finding.

    As the database administrator (shown here as "postgres"), verify the current setting of log_line_prefix by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_line_prefix"

    If log_line_prefix does not contain %m, %u, %d, %p, %r, %a, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Logging must be enabled to capture the identity of any user/subject or process associated with an event. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    To enable username, database name, process ID, remote host/port and application name in logging, as the database administrator (shown here as "postgres"), edit the following in postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    log_line_prefix = '< %m %u %d %p %r %a >'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000100-DB-000201'
  tag gid: 'V-261871'
  tag rid: 'SV-261871r1000618_rule'
  tag stig_id: 'CD16-00-001500'
  tag cci: ["CCI-001487"]
  tag nist: ["AU-3 f"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW log_line_prefix;', [conn.db]) do
    its('output.strip') { should cmp input('pg_log_line_prefix') }
  end

  rds_check_parameter_apply_status(conn)
end
