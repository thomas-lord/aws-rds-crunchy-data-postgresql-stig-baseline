control 'V-261891' do
  title 'If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGVER environment variables. Refer to supplementary content APPENDIX-H for PGVER.

    To check if password encryption is enabled, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW password_encryption"

    If password_encryption is not "scram-sha-256", this is a finding.

    To identify if any passwords have been stored without being hashed and salted, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -x -c "SELECT username, passwd FROM pg_shadow WHERE passwd IS NULL OR passwd NOT LIKE 'SCRAM-SHA-256%';"

    If any password is in plaintext, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To enable password_encryption, as the database administrator, edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    password_encryption = 'scram-sha-256'

    Institute a policy of not using the "WITH UNENCRYPTED PASSWORD" option with the CREATE ROLE/USER and ALTER ROLE/USER commands. (This option overrides the setting of the password_encryption configuration parameter.)

    As the system administrator, restart the server with the new configuration:

    # SYSTEMD SERVER ONLY
    $ sudo systemctl restart postgresql-${PGVER?}
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-261891'
  tag rid: 'SV-261891r1000970_rule'
  tag stig_id: 'CD16-00-003800'
  tag cci: ["CCI-000196"]
  # CCI-000196 has no NIST SP 800-53 Rev 5 mapping in the DISA CCI list (2025-01-23); Rev 4 reference used.
  tag nist: ["IA-5 (1) (c)"]
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

  describe sql.query('SHOW password_encryption;', [conn.db]) do
    its('output.strip') { should cmp input('pg_password_encryption') }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
