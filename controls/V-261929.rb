control 'V-261929' do
  title 'PostgreSQL must only accept end entity certificates issued by DOD PKI or DOD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), verify the following setting in postgresql.conf:

    $ sudo su - postgres
    $ psql -c "SHOW ssl_ca_file"
    $ psql -c "SHOW ssl_cert_file"

    If the database is not configured to use only DOD-approved certificates, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Revoke trust in any certificates not issued by a DOD-approved certificate authority.

    Configure PostgreSQL to accept only DOD and DOD-approved PKI end-entity certificates.

    To configure PostgreSQL to accept approved CAs, refer to the official PostgreSQL documentation: http://www.postgresql.org/docs/current/static/ssl-tcp.html

    For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag gid: 'V-261929'
  tag rid: 'SV-261929r1193220_rule'
  tag stig_id: 'CD16-00-008400'
  tag cci: ["CCI-002470"]
  tag nist: []
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW ssl_ca_file;', [input('pg_db')]) do
    its('output.strip') { should_not be_empty }
  end

  describe sql.query('SHOW ssl_cert_file;', [input('pg_db')]) do
    its('output.strip') { should_not be_empty }
  end
end
