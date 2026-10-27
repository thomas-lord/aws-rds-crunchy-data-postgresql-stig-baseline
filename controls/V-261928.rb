control 'V-261928' do
  title 'PostgreSQL must use NSA-approved cryptography to protect classified information in accordance with the data owner\'s requirements.'
  desc 'check', <<~EOT
    If PostgreSQL is deployed in an unclassified environment, this is not applicable.

    If PostgreSQL is not using NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, this is a finding.

    To check if PostgreSQL is configured to use SSL, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW ssl"

    If SSL is off, this is a finding.

    Consult network administration staff to determine whether the server is protected by NSA-approved encrypting devices. If not, this a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To configure PostgreSQL to use SSL as a database administrator (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameter:

    ssl = on

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}

    For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

    Deploy NSA-approved encrypting devices to protect the server on the network.
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag gid: 'V-261928'
  tag rid: 'SV-261928r1117186_rule'
  tag stig_id: 'CD16-00-008300'
  tag cci: ["CCI-002450"]
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
