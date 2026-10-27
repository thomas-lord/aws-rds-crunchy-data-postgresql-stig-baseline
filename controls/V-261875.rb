control 'V-261875' do
  title 'The audit information produced by PostgreSQL must be protected from unauthorized read access.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variable. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG.

    Review locations of audit logs, both internal to the database and database audit logs located at the operating system level.

    Verify appropriate controls and permissions exist to protect the audit information from unauthorized access.

    #### syslog Logging

    If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files.

    #### stderr Logging

    As the database administrator (shown here as "postgres"), check the current log_file_mode configuration by running the following:

    Note: Consult the organization's documentation on acceptable log privileges.

    $ sudo su - postgres
    $ psql -c "SHOW log_file_mode"

    If log_file_mode is not 600, this is a finding.

    Verify the log files have the set permissions in ${PGLOG?}:

    $ ls -l ${PGLOG?}/
    total 32
    -rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log
    -rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log
    -rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log
    -rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log
    -rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log 
    -rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log 

    If logs with 600 permissions do not exist in ${PGLOG?}, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. 

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    #### syslog Logging

    If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files.

    #### stderr Logging

    If PostgreSQL is configured to use stderr for logging, permissions of the log files can be set in postgresql.conf.

    As the database administrator (shown here as "postgres"), edit the following settings of logs in the postgresql.conf file:

    Note: Consult the organization's documentation on acceptable log privileges.

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    log_file_mode = 0600

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag gid: 'V-261875'
  tag rid: 'SV-261875r1000630_rule'
  tag stig_id: 'CD16-00-002000'
  tag cci: ["CCI-000162"]
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
  sql = postgres_session(conn.dba, input('pg_dba_password'), conn.host, conn.port)

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
