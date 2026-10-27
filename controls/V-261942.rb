control 'V-261942' do
  title 'PostgreSQL must generate audit records when privileges/permissions are added.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create a role by running the following SQL:

    Change the privileges of another user:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE bob"

    GRANT then REVOKE privileges from the role:

    $ psql -c "GRANT CONNECT ON DATABASE postgres TO bob"
    $ psql -c "REVOKE CONNECT ON DATABASE postgres FROM bob"

    postgres=# REVOKE CONNECT ON DATABASE postgres FROM bob;
    REVOKE

    postgres=# GRANT CONNECT ON DATABASE postgres TO bob;
    GRANT

    As the database administrator (shown here as "postgres"), verify the events were logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    < 2024-07-13 16:25:21.103 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE postgres TO bob,<none>
    < 2024-07-13 16:25:25.520 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,REVOKE,,,REVOKE CONNECT ON DATABASE postgres FROM bob,<none>

    If the above steps cannot verify that audit records are produced when privileges/permissions/role memberships are added, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL can be configured to audit these requests using pgaudit,. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed, the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):

    pgaudit.log = 'role'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag gid: 'V-261942'
  tag rid: 'SV-261942r1000831_rule'
  tag stig_id: 'CD16-00-009800'
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
