control 'V-261954' do
  title 'PostgreSQL must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.'
  desc <<~EOT
    Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

    For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of federal information and information systems, and FIPS Publication 200, Minimum Security Requirements for federal information and information systems.
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
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed, the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log='ddl, role, read, write'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag gid: 'V-261954'
  tag rid: 'SV-261954r1000867_rule'
  tag stig_id: 'CD16-00-011000'
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
