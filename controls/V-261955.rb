control 'V-261955' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to delete categories of information (e.g., classification levels/security levels) occur.'
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
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    All errors and denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log='ddl, role, read, write'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000502-DB-000349'
  tag gid: 'V-261955'
  tag rid: 'SV-261955r1000870_rule'
  tag stig_id: 'CD16-00-011100'
  tag cci: ["CCI-000172"]
  tag nist: []
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW shared_preload_libraries;', [input('pg_db')]) do
    its('output') { should match(/pgaudit/) }
  end

  describe sql.query('SHOW pgaudit.log;', [input('pg_db')]) do
    input('pgaudit_log_items').each do |item|
      its('output') { should match(/#{item}/) }
    end
  end
end
