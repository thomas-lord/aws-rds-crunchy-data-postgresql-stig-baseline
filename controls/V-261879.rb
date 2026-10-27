control 'V-261879' do
  title 'PostgreSQL must protect its audit configuration from unauthorized modification.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    All configurations for auditing and logging can be found in the postgresql.conf configuration file. By default, this file is owned by the database administrator account. 

    To check that the permissions of the postgresql.conf are owned by the database administrator with permissions of 0600, run the following as the database administrator (shown here as "postgres"):

    $ sudo su - postgres
    $ ls -la ${PGDATA?}

    If postgresql.conf is not owned by the database administrator or does not have 0600 permissions, this is a finding.

    #### stderr Logging

    To check that logs are created with 0600 permissions, check the following setting:

    $ sudo su - postgres
    $ psql -c "SHOW log_file_mode"

    If permissions are not 0600, this is a finding.

    #### syslog Logging

    If PostgreSQL is configured to use syslog, verify that the logs are owned by root and have 0600 permissions. If they are not, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Apply or modify access controls and permissions (both within PostgreSQL and in the file system/operating system) to tools used to view or modify audit log data. Tools must be configurable by authorized personnel only.

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    log_file_mode = 0600

    As the database administrator (shown here as "postgres"), change the ownership and permissions of configuration files in PGDATA:

    $ sudo su - postgres
    $ chown postgres:postgres ${PGDATA?}/*.conf
    $ chmod 0600 ${PGDATA?}/*.conf
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag gid: 'V-261879'
  tag rid: 'SV-261879r1000960_rule'
  tag stig_id: 'CD16-00-002400'
  tag cci: ["CCI-001494"]
  tag nist: ["AU-9 a"]
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
