control 'V-261931' do
  title 'PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'check', <<~EOT
    To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as "postgres"), run the following command:

    $ sudo su - postgres
    $ psql -c "SELECT * FROM pg_available_extensions where name='pgcrypto'"

    If data in the database requires encryption and pgcrypto is not available, this is a finding.

    If a disk or filesystem requires encryption, ask the system owner, database administrator (DBA), and system administrator (SA) to demonstrate the use of filesystem and/or disk-level encryption. If this is required and is not found, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection for information requiring cryptographic protection against disclosure.

    Secure the premises, equipment, and media to provide the required level of physical protection.

    The pgcrypto module provides cryptographic functions for PostgreSQL. Refer to supplementary content APPENDIX-E for documentation on installing pgcrypto.

    With pgcrypto installed, it is possible to insert encrypted data into the database:

    INSERT INTO accounts(username, password) VALUES ('bob', crypt('mypass', gen_salt('bf', 4));
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag gid: 'V-261931'
  tag rid: 'SV-261931r1018553_rule'
  tag stig_id: 'CD16-00-008600'
  tag cci: ["CCI-002476"]
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
