control 'V-261962' do
  title 'PostgreSQL must be able to generate audit records when successful accesses to objects occur.'
  desc <<~EOT
    Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

    In an SQL environment, types of access include, but are not necessarily limited to:
    SELECT
    INSERT
    UPDATE
    DELETE
    EXECUTE
  EOT
  desc 'check', <<~EOT
    As the database administrator, verify pgaudit is enabled by running the following SQL: 

    $ sudo su - postgres 
    $ psql -c "SHOW shared_preload_libraries" 

    If the output does not contain "pgaudit", this is a finding. 

    Verify that role, read, write, and ddl auditing are enabled: 

    $ psql -c "SHOW pgaudit.log" 

    If the output does not contain role, read, write, and ddl, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

    If logging is enabled, the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier.

    As the database administrator (shown here as "postgres"), edit postgresql.conf: 

    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 

    Edit the following parameters: 

    log_connections = on 
    log_line_prefix = '< %m %u %c: >' 
    pgaudit.log = 'read, write' 

    Where: 
    * %m is the time and date 
    * %u is the username 
    * %c is the session ID for the connection 

    As the system administrator, reload the server with the new configuration: 

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag gid: 'V-261962'
  tag rid: 'SV-261962r1000891_rule'
  tag stig_id: 'CD16-00-011800'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  rds_check_pgaudit_log(conn, sql)

  rds_check_parameter_apply_status(conn)
end
