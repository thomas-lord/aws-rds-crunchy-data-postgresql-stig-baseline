control 'V-261892' do
  title 'If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of passwords.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    As the database administrator (shown here as "postgres"), review the authentication entries in pg_hba.conf:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_hba.conf

    If any entries use the auth_method (last column in records) "password" or "md5", this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file and change all entries of "password" to "scram-sha-256":

    $ sudo su - postgres
    $ vi ${PGDATA?}/pg_hba.conf
    host all all .example.com scram-sha-256
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag gid: 'V-261892'
  tag rid: 'SV-261892r1000681_rule'
  tag stig_id: 'CD16-00-003900'
  tag cci: ["CCI-000197"]
  tag nist: ["IA-5 (1) (c)"]
  # AWS RDS PostgreSQL does not expose pg_hba.conf directly; the RDS-specific parameter
  # 'rds.force_ssl' enforces encrypted connections for all clients when enabled, which is
  # the RDS equivalent of ensuring no 'password'/'md5' plaintext-adjacent auth methods are
  # reachable over an unencrypted channel.
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

  describe sql.query("SHOW rds.force_ssl;", [conn.db]) do
    its('output.strip') { should cmp '1' }
  end

  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
