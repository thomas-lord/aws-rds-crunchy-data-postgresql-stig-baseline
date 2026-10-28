control 'V-261865' do
  title 'PostgreSQL must initiate session auditing upon startup.'
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), check the current settings by running the following SQL: 

    $ sudo su - postgres 
    $ psql -c "SHOW shared_preload_libraries" 

    If pgaudit is not in the current setting, this is a finding. 

    As the database administrator (shown here as "postgres"), check the current settings by running the following SQL: 

    $ psql -c "SHOW log_destination" 

    If stderr or syslog are not in the current setting, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to enable auditing.

    To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

    For session logging, using pgaudit is recommended. For instructions on how to setup pgaudit, refer to supplementary content APPENDIX-B.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-261865'
  tag rid: 'SV-261865r1000600_rule'
  tag stig_id: 'CD16-00-000900'
  tag cci: ["CCI-001464"]
  tag nist: ["AU-14 (1)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  # Read the input outside the describe block: inside one, RSpec treats `input` as an
  # example-defining method and returns an RSpec::Core::Example, not the value.
  pgaudit_log_items = input('pgaudit_log_items')
  describe sql.query('SHOW pgaudit.log;', [conn.db]) do
    pgaudit_log_items.each do |item|
      its('output') { should match(/#{item}/) }
    end
  end

  rds_check_parameter_apply_status(conn)
end
