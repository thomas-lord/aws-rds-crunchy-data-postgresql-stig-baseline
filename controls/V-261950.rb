control 'V-261950' do
  title 'PostgreSQL must generate audit records when privileges/permissions are deleted.'
  desc 'check', <<~EOT
    As the database administrator, verify pgaudit is enabled by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW shared_preload_libraries"

    If the output does not contain pgaudit, this is a finding.

    Verify that role, read, write, and ddl auditing are enabled:

    $ psql -c "SHOW pgaudit.log"

    If the output does not contain role, read, write, and ddl, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed, the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log = 'role'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000499-DB-000330'
  tag gid: 'V-261950'
  tag rid: 'SV-261950r1000855_rule'
  tag stig_id: 'CD16-00-010600'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
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
