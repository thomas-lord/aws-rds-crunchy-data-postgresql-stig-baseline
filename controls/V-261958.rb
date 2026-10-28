control 'V-261958' do
  title 'PostgreSQL must generate audit records for all privileged activities or other system-level access.'
  desc <<~EOT
    Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    System documentation should include a definition of the functionality considered privileged.

    A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:
    CREATE
    ALTER
    DROP
    GRANT
    REVOKE
    DENY

    There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples in SQL include:

    TRUNCATE TABLE;
    DELETE, or
    DELETE affecting more than n rows, for some n, or
    DELETE without a WHERE clause;

    UPDATE or
    UPDATE affecting more than n rows, for some n, or
    UPDATE without a WHERE clause;

    any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.

    Depending on the capabilities of PostgreSQL and the design of the database and associated applications, audit logging may be achieved by means of PostgreSQL auditing features, database triggers, other mechanisms, or a combination of these.

    Note that it is particularly important to audit and tightly control any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.
  EOT
  desc 'check', <<~EOT
    As the database administrator, verify pgaudit is enabled by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW shared_preload_libraries"

    If the output does not contain pgaudit, this is a finding.

    Verify that role, read, write, and ddl auditing are enabled:

    $ psql -c "SHOW pgaudit.log"

    If the output does not contain role, read, write, and ddl, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    With pgaudit installed the following configurations can be made:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameters (or edit existing parameters):
    shared_preload_libraries = 'pgaudit'
    pgaudit.log='ddl, role, read, write'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000504-DB-000354'
  tag gid: 'V-261958'
  tag rid: 'SV-261958r1000879_rule'
  tag stig_id: 'CD16-00-011400'
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
