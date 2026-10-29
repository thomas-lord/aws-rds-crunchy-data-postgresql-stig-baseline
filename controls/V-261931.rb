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

    checks, manual_note = rds_storage_encryption_checks(conn)
    # In-database encryption: the STIG requires pgcrypto to be *available* (listed in
    # pg_available_extensions), not necessarily installed via CREATE EXTENSION.
    checks << rds_check('pgcrypto available (pg_available_extensions)') do
      version = sql.query("SELECT default_version FROM pg_available_extensions WHERE name='pgcrypto';", [conn.db]).output.strip
      [version.match?(/\A\d+(\.\d+)*\z/), version.empty? ? 'not available' : "version #{version}"]
    end
    rds_review_results(checks, manual_note).each do |result|
      describe(result[:title]) { instance_exec(&result[:report]) }
    end
  else
    describe 'The organization has indicated (via the pg_encryption_of_data_at_rest_required input) that encryption of this data at rest is not required by the application owner/Authorizing Official; this control is Not a Finding.' do
      skip 'The organization has indicated (via the pg_encryption_of_data_at_rest_required input) that encryption of this data at rest is not required by the application owner/Authorizing Official; this control is Not a Finding.'
    end
  end
end
