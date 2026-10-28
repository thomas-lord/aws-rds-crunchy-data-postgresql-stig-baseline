control 'V-261880' do
  title 'PostgreSQL must protect its audit features from unauthorized removal.'
  desc <<~EOT
    Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the deletion of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    As the database administrator (shown here as "postgres"), verify the permissions of PGDATA: 

    $ sudo su - postgres 
    $ ls -la ${PGDATA?} 

    If PGDATA is not owned by postgres:postgres or if files can be accessed by others, this is a finding. 

    As the system administrator, verify the permissions of pgsql shared objects and compiled binaries: 

    $ ls -la /usr/pgsql-${PGVER?}/bin
    $ ls -la /usr/pgsql-${PGVER?}/include
    $ ls -la /usr/pgsql-${PGVER?}/lib
    $ ls -la /usr/pgsql-${PGVER?}/share 

    If any of these are not owned by root:root, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    As the system administrator, change the permissions of PGDATA: 

    $ sudo chown -R postgres:postgres ${PGDATA?} 
    $ sudo chmod 700 ${PGDATA?} 

    As the system administrator, change the permissions of pgsql: 

    $ sudo chown -R root:root /usr/pgsql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag gid: 'V-261880'
  tag rid: 'SV-261880r1000959_rule'
  tag stig_id: 'CD16-00-002500'
  tag cci: ["CCI-001495"]
  tag nist: ["AU-9 a"]
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).'
  end
end
