control 'V-261886' do
  title 'Unused database components, PostgreSQL software, and database objects must be removed.'
  desc <<~EOT
    Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

    PostgreSQL must adhere to the principles of least functionality by providing only essential capabilities.
  EOT
  desc 'check', <<~EOT
    To get a list of all extensions installed, use the following commands:

    $ sudo su - postgres
    $ psql -c "select * from pg_extension where extname != 'plpgsql'"

    If any extensions exist that are not approved, this is a finding.
  EOT
  desc 'fix', <<~EOT
    To remove extensions, use the following commands:

    $ sudo su - postgres
    $ psql -c "DROP EXTENSION <extension_name>"

    Note: Removal of plpgsql is not recommended.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag gid: 'V-261886'
  tag rid: 'SV-261886r1000951_rule'
  tag stig_id: 'CD16-00-003200'
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # Extensions are installed per database, so every database is checked. plpgsql is built in.
  approved = input('pg_approved_extensions')
  extensions, unreadable = rds_query_each_database(conn, sql, "SELECT extname FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1;", /\A[\w-]+\z/)
  installed = extensions.map { |database, extension| "#{extension} (#{database})" }
  unapproved = extensions.reject { |_, extension| approved.include?(extension) }.map { |database, extension| "#{extension} (#{database})" }
  describe "Installed extensions besides plpgsql: #{installed.empty? ? 'none' : installed.join(', ')}" do
    it 'should be readable in every database (the scan account needs CONNECT on each)' do
      expect(unreadable).to be_empty
    end
    it 'should all be approved via the pg_approved_extensions input' do
      expect(unapproved).to be_empty
    end
  end
end
