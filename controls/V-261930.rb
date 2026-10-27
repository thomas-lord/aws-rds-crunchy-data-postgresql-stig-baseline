control 'V-261930' do
  title 'PostgreSQL must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'check', <<~EOT
    Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

    If no information is identified as requiring such protection, this is not a finding.

    Review the configuration of PostgreSQL, operating system/file system, and additional software as relevant.

    If any of the information defined as requiring cryptographic protection from modification is not encrypted in a manner that provides the required level of protection, this is a finding.

    One possible way to encrypt data within PostgreSQL is to use pgcrypto extension.

    To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as "postgres"), run the following command:

    $ sudo su - postgres
    $ psql -c "SELECT * FROM pg_available_extensions where name='pgcrypto'"

    If data in the database requires encryption and pgcrypto is not available, this is a finding.

    If disk or filesystem requires encryption, ask the system owner, database administrator (DBA), and system administrator (SA) to demonstrate filesystem or disk level encryption.

    If this is required and is not found, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection.

    The pgcrypto module provides cryptographic functions for PostgreSQL. Refer to supplementary content APPENDIX-E for documentation on installing pgcrypto.

    With pgcrypto installed, it is possible to insert encrypted data into the database:

    INSERT INTO accounts(username, password) VALUES ('bob', crypt('mypass', gen_salt('bf', 4));
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag gid: 'V-261930'
  tag rid: 'SV-261930r1211024_rule'
  tag stig_id: 'CD16-00-008500'
  tag cci: ["CCI-002475"]
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

    # Disk-level encryption: on RDS this is storage encryption with an AWS KMS key,
    # which covers the data volume, automated backups, snapshots, and read replicas.
    if conn.aws_available?
      describe "RDS storage encryption at rest (KmsKeyId: #{conn.aws_instance_attr('KmsKeyId') || 'none'})" do
        subject { conn.aws_instance_attr('StorageEncrypted') }
        it { should cmp true }
      end
    else
      describe 'RDS storage encryption at rest cannot be checked without AWS CLI discovery (aws_db_instance_identifier + aws CLI); manually verify "Encryption: Enabled" with a KMS key on the instance\'s Configuration tab in the RDS console.' do
        skip 'RDS storage encryption at rest cannot be checked without AWS CLI discovery (aws_db_instance_identifier + aws CLI); manually verify "Encryption: Enabled" with a KMS key on the instance\'s Configuration tab in the RDS console.'
      end
    end

    # In-database encryption: the STIG requires pgcrypto to be *available* (listed in
    # pg_available_extensions), not necessarily installed via CREATE EXTENSION.
    describe sql.query("SELECT default_version FROM pg_available_extensions WHERE name='pgcrypto';", [conn.db]) do
      its('output.strip') { should match(/\A\d+(\.\d+)*\z/) }
    end
  else
    describe 'The organization has indicated (via the pg_encryption_of_data_at_rest_required input) that encryption of this data at rest is not required by the application owner/Authorizing Official; this control is Not a Finding.' do
      skip 'The organization has indicated (via the pg_encryption_of_data_at_rest_required input) that encryption of this data at rest is not required by the application owner/Authorizing Official; this control is Not a Finding.'
    end
  end
end
