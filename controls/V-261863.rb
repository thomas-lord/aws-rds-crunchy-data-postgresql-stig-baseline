control 'V-261863' do
  title 'PostgreSQL must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variable. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG.

    As the database administrator (shown here as "postgres"), check if pgaudit is enabled by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW shared_preload_libraries"

    If pgaudit is not found in the results, this is a finding.

    As the database administrator (shown here as "postgres"), list all role memberships for the database:

    $ sudo su - postgres
    $ psql -c "\du"

    Verify the query was logged:

    $ sudo su - postgres
    $ cat ${PGLOG?}/<latest_log>

    This should, as an example, return (among other rows):
    < 2024-02-01 19:13:38.276 UTC psql postgres postgres [local] 15639 >LOG:  duration: 29.932 ms  statement: SELECT r.rolname, r.rolsuper, r.rolinherit,
              r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
              r.rolconnlimit, r.rolvaliduntil
            , r.rolreplication
            , r.rolbypassrls
            FROM pg_catalog.pg_roles r
            WHERE r.rolname !~ '^pg_'
            ORDER BY 1;

    If audit records are not produced, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters): 

    pgaudit.log_catalog = 'on'
    pgaudit.log = 'read'

    Note: For this requirement the pgaudit.log must contain 'read' however APPENDIX-C suggests setting pgaudit.log='ddl, role, read, write' to fulfill all requirements.

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag gid: 'V-261863'
  tag rid: 'SV-261863r1000954_rule'
  tag stig_id: 'CD16-00-000700'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW shared_preload_libraries;', [conn.db]) do
    its('output') { should match(/pgaudit/) }
  end

  # Read the input outside the describe block: inside one, RSpec treats `input` as an
  # example-defining method and returns an RSpec::Core::Example, not the value.
  pgaudit_log_items = input('pgaudit_log_items')
  describe sql.query('SHOW pgaudit.log;', [conn.db]) do
    pgaudit_log_items.each do |item|
      its('output') { should match(/#{item}/) }
    end
  end

  rds_check_parameter_apply_status(conn)
end
