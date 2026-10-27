control 'V-261878' do
  title 'PostgreSQL must protect its audit features from unauthorized access.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER, and APPENDIX-I for PGLOG. Only the database owner and superuser can alter configuration of PostgreSQL.

    Ensure the PGLOG directory is owned by postgres user and group:

    $ sudo su - postgres
    $ ls -la ${PGLOG?} 

    If PGLOG is not owned by the database owner, this is a finding. 

    Ensure the data directory is owned by postgres user and group. 

    $ sudo su - postgres
    $ ls -la ${PGDATA?}

    If PGDATA is not owned by the database owner, this is a finding.

    Ensure the pgaudit installation is owned by root:

    $ sudo su - postgres
    $ ls -la /usr/pgsql-${PGVER?}/share/extension/pgaudit*

    If the pgaudit installation is not owned by root, this is a finding.

    As the database administrator (shown here as "postgres"), run the following SQL to list all roles and their privileges:

    $ sudo su - postgres
    $ psql -x -c "\du"

    If any role has "superuser" that should not, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER and APPENDIX-I for PGLOG.

    If PGLOG or PGDATA are not owned by postgres user and group, configure them as follows: 

    $ sudo chown -R postgres:postgres ${PGDATA?}
    $ sudo chown -R postgres:postgres ${PGLOG?}

    If the pgaudit installation is not owned by root user and group, configure it as follows:

    $ sudo chown -R root:root /usr/pgsql-${PGVER?}/share/extension/pgaudit*

    To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag gid: 'V-261878'
  tag rid: 'SV-261878r1000958_rule'
  tag stig_id: 'CD16-00-002300'
  tag cci: ["CCI-001493"]
  tag nist: []
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).'
  end
end
