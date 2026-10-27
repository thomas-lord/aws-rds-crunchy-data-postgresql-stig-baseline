control 'V-261861' do
  title 'PostgreSQL must provide audit record generation capability for DOD-defined auditable events within all DBMS/database components.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variables. Refer to supplementary content APPENDIX-I for instructions on configuring PGVER.

    Check PostgreSQL audit logs to determine whether organization-defined auditable events are being audited by the system.

    For example, if the organization defines 'CREATE TABLE' as an auditable event, issuing the following command should return a result:

    $ sudo su - postgres
    $ psql -c "CREATE TABLE example (id int)"
    $ grep 'AUDIT:.*,CREATE TABLE.*example' ${PGLOG?}/<latest_log>
    $ psql -c 'DROP TABLE example;'

    If organization-defined auditable events are not being audited, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to generate audit records for at least the DOD minimum set of events.

    Using "pgaudit", PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-261861'
  tag rid: 'SV-261861r1000588_rule'
  tag stig_id: 'CD16-00-000500'
  tag cci: ["CCI-000169"]
  tag nist: []
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
