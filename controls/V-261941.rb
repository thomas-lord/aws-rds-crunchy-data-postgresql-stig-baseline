control 'V-261941' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to access categories of information (e.g., classification levels/security levels) occur.'
  desc <<~EOT
    Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

    To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

    For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of federal information and information systems, and FIPS Publication 200, Minimum Security Requirements for federal information and information systems.
  EOT
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW pgaudit.log"

    If pgaudit.log does not contain, "ddl, write, role", this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Configure PostgreSQL to produce audit records when unsuccessful attempts to access categories of information occur.

    All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    With pgaudit installed the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log = 'ddl, write, role'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000494-DB-000345'
  tag gid: 'V-261941'
  tag rid: 'SV-261941r1000828_rule'
  tag stig_id: 'CD16-00-009700'
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
