control 'V-261870' do
  title 'PostgreSQL must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variables. Refer to supplementary content APPENDIX-I for instructions on configuring them.

    As a database administrator (shown here as "postgres"), create a table, insert a value, alter the table and update the table by running the following SQL:

    CREATE TABLE stig_test(id INT);
    INSERT INTO stig_test(id) VALUES (0);
    ALTER TABLE stig_test ADD COLUMN name text;
    UPDATE stig_test SET id = 1 WHERE id = 0;

    As a user without access to the stig_test table, run the following SQL:

    INSERT INTO stig_test(id) VALUES (1);
    ALTER TABLE stig_test DROP COLUMN name;
    UPDATE stig_test SET id = 0 WHERE id = 1;

    The prior SQL should generate errors:

    ERROR: permission denied for relation stig_test
    ERROR: must be owner of relation stig_test
    ERROR: permission denied for relation stig_test

    As the database administrator, drop the test table by running the following SQL:

    DROP TABLE stig_test;

    Verify the errors were logged:

    $ sudo su - postgres
    $ cat ${PGLOG?}/<latest_logfile>
    < 2024-02-23 14:51:31.103 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE stig_test(id INT);,<none>
    < 2024-02-23 14:51:44.835 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,2,1,WRITE,INSERT,,,INSERT INTO stig_test(id) VALUES (0);,<none>
    < 2024-02-23 14:53:25.805 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,3,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test ADD COLUMN name text;,<none>
    < 2024-02-23 14:53:54.381 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >LOG: AUDIT: SESSION,4,1,WRITE,UPDATE,,,UPDATE stig_test SET id = 1 WHERE id = 0;,<none>
    < 2024-02-23 14:54:20.832 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >ERROR: permission denied for relation stig_test
    < 2024-02-23 14:54:20.832 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >STATEMENT: INSERT INTO stig_test(id) VALUES (1);
    < 2024-02-23 14:54:41.032 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >ERROR: must be owner of relation stig_test
    < 2024-02-23 14:54:41.032 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >STATEMENT: ALTER TABLE stig_test DROP COLUMN name;
    < 2024-02-23 14:54:54.378 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >ERROR: permission denied for relation stig_test
    < 2024-02-23 14:54:54.378 UTC psql postgres postgres 570bf22a.3af2 2024-04-11 14:51:22 EDT [local] >STATEMENT: UPDATE stig_test SET id = 0 WHERE id = 1;
    < 2024-02-23 14:55:23.723 UTC psql postgres postgres 570bf307.3b0a 2024-04-11 14:55:03 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,DROP TABLE,,,DROP TABLE stig_test;,<none>

    If audit records exist without the outcome of the event that occurred, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Using pgaudit, PostgreSQL can be configured to audit various facets of PostgreSQL. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit. 

    All errors, denials, and unsuccessful requests are logged if logging is enabled. Refer to supplementary content APPENDIX-C for documentation on enabling logging.

    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    With pgaudit and logging enabled, set the configuration settings in postgresql.conf, as the database administrator (shown here as "postgres"), to the following: 

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf 
    pgaudit.log_catalog='on' 
    pgaudit.log_level='log' 
    pgaudit.log_parameter='on' 
    pgaudit.log_statement_once='off' 
    pgaudit.log='ddl, role, read, write' 

    Tune the following logging configurations in postgresql.conf: 

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf 
    log_line_prefix = '< %m %u %d %e: >' 
    log_error_verbosity = default 

    As the system administrator, restart PostgreSQL: 

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag gid: 'V-261870'
  tag rid: 'SV-261870r1000615_rule'
  tag stig_id: 'CD16-00-001400'
  tag cci: ["CCI-000134"]
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
