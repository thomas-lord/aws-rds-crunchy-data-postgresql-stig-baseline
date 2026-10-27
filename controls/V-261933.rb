control 'V-261933' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during reception.'
  desc 'check', <<~EOT
    If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

    As the database administrator (shown here as "postgres"), verify SSL is enabled in postgresql.conf by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW ssl" 

    If SSL is off, this is a finding.

    If PostgreSQL, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Implement protective measures against unauthorized disclosure and modification during reception.

    To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G for instructions on enabling SSL.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag gid: 'V-261933'
  tag rid: 'SV-261933r1000804_rule'
  tag stig_id: 'CD16-00-008900'
  tag cci: ["CCI-002422"]
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
  sql = postgres_session(conn.dba, input('pg_dba_password'), conn.host, conn.port)

  describe sql.query('SHOW ssl;', [conn.db]) do
    its('output.strip') { should cmp input('pg_ssl') }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
