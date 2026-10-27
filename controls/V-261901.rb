control 'V-261901' do
  title 'PostgreSQL must protect the confidentiality and integrity of all information at rest.'
  desc 'check', <<~EOT
    If the application owner and Authorizing Official (AO) have determined that encryption of data at rest is NOT required, this is not a finding.

    One possible way to encrypt data within PostgreSQL is to use the pgcrypto extension.

    To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as "postgres"), run the following command:

    $ sudo su - postgres
    $ psql -c "SELECT * FROM pg_available_extensions where name='pgcrypto'"

    If data in the database requires encryption and pgcrypto is not available, this is a finding.

    If disk or filesystem requires encryption, ask the system owner, database administrator (DBA), and system administrator (SA) to demonstrate the use of disk-level encryption. If this is required and is not found, this is a finding.

    If controls do not exist or are not enabled, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.

    The pgcrypto module provides cryptographic functions for PostgreSQL. Refer to supplementary content APPENDIX-E for documentation on installing pgcrypto.

    With pgcrypto installed, it is possible to insert encrypted data into the database:

    INSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('xdes')));
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag gid: 'V-261901'
  tag rid: 'SV-261901r1000708_rule'
  tag stig_id: 'CD16-00-005200'
  tag cci: ["CCI-001199"]
  tag nist: []
  if input('pg_encryption_of_data_at_rest_required')
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

    describe sql.query("SELECT installed_version FROM pg_available_extensions WHERE name='pgcrypto';", [conn.db]) do
      its('output.strip') { should match(/\A\d+(\.\d+)*\z/) }
    end
  else
    describe 'The organization has indicated (via the pg_encryption_of_data_at_rest_required input) that encryption of this data at rest is not required by the application owner/Authorizing Official; this control is Not a Finding.' do
      skip 'The organization has indicated (via the pg_encryption_of_data_at_rest_required input) that encryption of this data at rest is not required by the application owner/Authorizing Official; this control is Not a Finding.'
    end
  end
end
