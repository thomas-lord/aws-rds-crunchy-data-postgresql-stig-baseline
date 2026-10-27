control 'V-261904' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Review the permissions granted to users by the operating system/file system on the database files, database log files and database backup files.

    To verify that all files are owned by the database administrator and have the correct permissions, run the following as the database administrator (shown here as "postgres"):

    $ sudo su - postgres
    $ ls -lR ${PGDATA?}

    If any files are not owned by the database administrator or allow anyone but the database administrator to read/write/execute, this is a finding.

    If any user/role that is not an authorized system administrator with a need-to-know or database administrator with a need-to-know, or a system account for running PostgreSQL processes, is permitted to read/view any of these files, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Configure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.

    Any files (for example: extra configuration files) created in ${PGDATA?} must be owned by the database administrator, with only owner permissions to read, write, and execute.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag gid: 'V-261904'
  tag rid: 'SV-261904r1137658_rule'
  tag stig_id: 'CD16-00-005600'
  tag cci: ["CCI-001090"]
  tag nist: []
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/patching of the PostgreSQL engine for RDS-hosted instances. Customers do not have OS-level or file-system access required to evaluate this control.' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/patching of the PostgreSQL engine for RDS-hosted instances. Customers do not have OS-level or file-system access required to evaluate this control.'
  end
end
