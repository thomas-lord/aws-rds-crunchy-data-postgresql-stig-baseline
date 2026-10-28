control 'V-261881' do
  title 'PostgreSQL must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to PostgreSQL.'
  desc <<~EOT
    If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    As the database administrator (shown here as "postgres"), check the permissions of configuration files for the database:

    $ sudo su - postgres
    $ ls -la ${PGDATA?}

    If any files are not owned by the database owner or have permissions allowing others to modify (write) configuration files, this is a finding.

    As the server administrator, check the permissions on the shared libraries for PostgreSQL:

    $ sudo ls -la /usr/pgsql-${PGVER?} 
    $ sudo ls -la /usr/pgsql-${PGVER?}/bin
    $ sudo ls -la /usr/pgsql-${PGVER?}/include
    $ sudo ls -la /usr/pgsql-${PGVER?}/lib
    $ sudo ls -la /usr/pgsql-${PGVER?}/share

    If any files are not owned by root or have permissions allowing others to modify (write) configuration files, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    As the database administrator (shown here as "postgres"), change the ownership and permissions of configuration files in PGDATA: 

    $ sudo su - postgres 
    $ chown postgres:postgres ${PGDATA?}/postgresql.conf 
    $ chmod 0600 ${PGDATA?}/postgresql.conf 

    As the server administrator, change the ownership and permissions of shared objects in /usr/pgsql-${PGVER?}/*.so 

    $ sudo chown root:root /usr/pgsql-${PGVER?}/lib/*.so 
    $ sudo chmod 0755 /usr/pgsql-${PGVER?}/lib/*.so 

    As the service administrator, change the ownership and permissions of executables in /usr/pgsql-${PGVER?}/bin: 

    $ sudo chown root:root /usr/pgsql-${PGVER?}/bin/* 
    $ sudo chmod 0755 /usr/pgsql-${PGVER?}/bin/*
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag gid: 'V-261881'
  tag rid: 'SV-261881r1000648_rule'
  tag stig_id: 'CD16-00-002600'
  tag cci: ["CCI-001499"]
  tag nist: ["CM-5 (6)"]
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).'
  end
end
