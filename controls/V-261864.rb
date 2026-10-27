control 'V-261864' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variables. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG.

    As the database administrator (shown here as "postgres"), create a role "bob" by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE bob"

    Attempt to retrieve information from the pg_authid table:

    $ psql -c "SET ROLE bob; SELECT * FROM pg_authid"
    $ psql -c "DROP ROLE bob;"

    As the database administrator (shown here as "postgres"), verify the event was logged in PGLOG:

    $ sudo su - postgres
    $ cat ${PGLOG?}/<latest_log>
    < 2024-02-13 16:49:58.864 UTC postgres postgres ERROR: > permission denied for relation pg_authid
    < 2024-02-13 16:49:58.864 UTC postgres postgres STATEMENT: > SELECT * FROM pg_authid

    If the above steps cannot verify that audit records are produced when PostgreSQL denies retrieval of privileges/permissions/role memberships, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges occur.

    All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag gid: 'V-261864'
  tag rid: 'SV-261864r1000597_rule'
  tag stig_id: 'CD16-00-000800'
  tag cci: ["CCI-000172"]
  tag nist: []
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW shared_preload_libraries;', [input('pg_db')]) do
    its('output') { should match(/pgaudit/) }
  end

  describe sql.query('SHOW pgaudit.log;', [input('pg_db')]) do
    input('pgaudit_log_items').each do |item|
      its('output') { should match(/#{item}/) }
    end
  end
end
