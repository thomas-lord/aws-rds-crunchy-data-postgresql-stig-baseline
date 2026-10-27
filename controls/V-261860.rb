control 'V-261860' do
  title 'PostgreSQL must protect against a user falsely repudiating having performed organization-defined actions.'
  desc 'check', <<~EOT
    As the database administrator, review the current log_line_prefix settings by running the following SQL: 

    $ sudo su - postgres 
    $ psql -c "SHOW log_line_prefix" 

    If log_line_prefix does not contain at least '< %m %a %u %d %r %p >', this is a finding. 

    Review the current shared_preload_libraries settings by running the following SQL: 

    $ psql -c "SHOW shared_preload_libraries" 

    If shared_preload_libraries does not contain "pgaudit", this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Configure the database to supply additional auditing information to protect against a user falsely repudiating having performed organization-defined actions. 

    Using "pgaudit", PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit. 

    To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

    Modify the configuration of audit logs to include details identifying the individual user: 

    As the database administrator (shown here as "postgres"), edit postgresql.conf: 

    $ sudo su - postgres 
    $ vi ${PGDATA?}/postgresql.conf 

    Extra parameters can be added to the setting log_line_prefix to identify the user: 

    log_line_prefix = '< %m %a %u %d %r %p >' 

    As the system administrator, reload the server with the new configuration: 

    $ sudo systemctl reload postgresql-${PGVER?}

    Use accounts assigned to individual users. Where the application connects to PostgreSQL using a standard, shared account, ensure it also captures the individual user identification and passes it to PostgreSQL.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag gid: 'V-261860'
  tag rid: 'SV-261860r1000977_rule'
  tag stig_id: 'CD16-00-000400'
  tag cci: ["CCI-000166"]
  tag nist: ["AU-10"]
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

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  describe sql.query('SHOW pgaudit.log;', [conn.db]) do
    input('pgaudit_log_items').each do |item|
      its('output') { should match(/#{item}/) }
    end
  end

  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
