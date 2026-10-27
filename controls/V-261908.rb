control 'V-261908' do
  title 'PostgreSQL must provide nonprivileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'check', <<~EOT
    To check the level of detail for errors exposed to clients, as the DBA (shown here as "postgres"), run the following:

    $ sudo su - postgres
    $ psql -c "SHOW client_min_messages;"

    If client_min_messages is not set to error, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    As the database administrator, edit "postgresql.conf": 

    $ sudo su - postgres 
    $ vi $PGDATA/postgresql.conf 

    Change the client_min_messages parameter to be "error": 

    client_min_messages = error 

    Reload the server with the new configuration (this just reloads settings currently in memory; it will not cause an interruption): 

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag gid: 'V-261908'
  tag rid: 'SV-261908r1000729_rule'
  tag stig_id: 'CD16-00-006000'
  tag cci: ["CCI-001312"]
  tag nist: []
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW client_min_messages;', [input('pg_db')]) do
    its('output.strip') { should cmp input('pg_client_min_messages') }
  end
end
