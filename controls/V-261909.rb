control 'V-261909' do
  title 'PostgreSQL must reveal detailed error messages only to the information system security officer (ISSO), information system security manager (ISSM), system administrator (SA), and database administrator (DBA).'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

    Check PostgreSQL settings and custom database code to determine if detailed error messages are ever displayed to unauthorized individuals.

    To check the level of detail for errors exposed to clients, as the DBA (shown here as "postgres"), run the following:

    $ sudo su - postgres
    $ psql -c "SHOW client_min_messages;"

    If client_min_messages is not set to error, this is a finding.

    If detailed error messages are displayed to individuals not authorized to view them, this is a finding.

    #### stderr Logging

    Logs may contain detailed information and should only be accessible by the database owner.

    As the database administrator, verify the following settings of logs.

    Note: Consult the organization's documentation on acceptable log privileges.

    $ sudo su - postgres
    $ psql -c "SHOW log_file_mode;" 

    Verify the log files have the set configurations.

    $ ls -l ${PGLOG?}
    total 32
    -rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log
    -rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log
    -rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log
    -rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log
    -rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log
    -rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log

    If logs are not owned by the database administrator or have permissions that are not 0600, this is a finding.

    #### syslog Logging

    If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files. If the logs are not owned by root or have permissions that are not 0600, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    To set the level of detail for error messages exposed to clients, as the DBA (shown here as "postgres"), run the following commands:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    client_min_messages = error
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag gid: 'V-261909'
  tag rid: 'SV-261909r1000980_rule'
  tag stig_id: 'CD16-00-006100'
  tag cci: ["CCI-001314"]
  tag nist: []
  conn = aws_rds_connection(
    aws_instance_id: input('aws_db_instance_identifier'),
    region: input('aws_region'),
    profile: input('aws_cli_profile'),
    host: input('pg_host'),
    port: input('pg_port'),
    db: input('pg_db'),
    dba: input('pg_dba')
  )
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW client_min_messages;', [conn.db]) do
    its('output.strip') { should cmp input('pg_client_min_messages') }
  end

  describe sql.query('SHOW log_file_mode;', [conn.db]) do
    its('output.strip') { should cmp input('pg_log_file_mode') }
  end


  if conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end
end
