control 'V-261876' do
  title 'The audit information produced by PostgreSQL must be protected from unauthorized modification.'
  desc 'check', <<~EOT
    Review locations of audit logs, both internal to the database and database audit logs located at the operating system level. 

    Verify there are appropriate controls and permissions to protect the audit information from unauthorized modification. 

    Note: The following instructions use the PGLOG environment variable. Refer to supplementary content APPENDIX-I for instructions on configuring PGLOG. 

    #### stderr Logging 

    If the PostgreSQL server is configured to use stderr for logging, the logs will be owned by the database owner (usually postgres user) with a default permissions level of 0600. The permissions can be configured in postgresql.conf. 

    To check the permissions for log files in postgresql.conf, as the database owner (shown here as "postgres"), run the following command: 

    $ sudo su - postgres 
    $ psql -c "show log_file_mode;" 

    If the permissions are not 0600, this is a finding. 

    As the database owner (shown here as "postgres"), list the permissions of the logs: 

    $ sudo su - postgres 
    $ ls -la ${PGLOG?} 

    If logs are not owned by the database owner (shown here as "postgres") and are not the same permissions as configured in postgresql.conf, this is a finding. 

    #### syslog Logging 

    If the PostgreSQL server is configured to use syslog for logging, consult the organization syslog setting for permissions and ownership of logs.
  EOT
  desc 'fix', <<~EOT
    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

    #### stderr Logging

    With stderr logging enabled, as the database owner (shown here as "postgres"), set the following parameter in postgresql.conf:

    $ vi ${PGDATA?}/postgresql.conf
    log_file_mode = 0600

    To change the owner and permissions of the log files, run the following:

    $ chown postgres:postgres ${PGDATA?}/${PGLOG?}
    $ chmod 0700 ${PGDATA?}/${PGLOG?}
    $ chmod 600 ${PGDATA?}/${PGLOG?}/*.log

    #### syslog Logging

    If PostgreSQL is configured to use syslog for logging, the log files must be configured to be owned by root with 0600 permissions.

    $ chown root:root <log directory name>/<log_filename>
    $ chmod 0700 <log directory name>
    $ chmod 0600 <log directory name>/*.log
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag gid: 'V-261876'
  tag rid: 'SV-261876r1000978_rule'
  tag stig_id: 'CD16-00-002100'
  tag cci: ["CCI-000163"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
