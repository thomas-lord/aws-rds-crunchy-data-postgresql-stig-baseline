control 'V-261931' do
  title 'PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc <<~EOT
    PostgreSQLs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to PostgreSQL or implemented via additional software or operating system/file system settings, as appropriate to the situation.

    Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

    The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.
  EOT
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
  tag nist: ["SC-28 (1)"]
  if input('pg_encryption_of_data_at_rest_required')
    conn = rds_connection
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
