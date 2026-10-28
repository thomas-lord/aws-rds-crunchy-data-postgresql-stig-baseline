control 'V-283674' do
  title 'PostgreSQL products must be a version supported by the vendor.'
  desc <<~EOT
    Unsupported software and systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

    Software and systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

    When maintenance updates and patches are no longer available, software is no longer considered supported and should be upgraded or decommissioned.
  EOT
  desc 'check', <<~EOT
    If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:

    To list the version of installed PostgreSQL using psql:

    $ sudo su - postgres
    $ psql --version

    To list the current version of software for RPM:

    $ rpm -qa | grep postgres

    To list the current version of software for APT:

    $ apt-cache policy postgres

    All versions of PostgreSQL are listed here: http://www.postgresql.org/support/versioning/

    All security-relevant software updates for PostgreSQL are listed here: http://www.postgresql.org/support/security/

    If PostgreSQL is not at the latest version, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Upgrade or install a version of the product supported by the vendor.
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-001035-DB-000323'
  tag gid: 'V-283674'
  tag rid: 'SV-283674r1193281_rule'
  tag stig_id: 'CD16-00-009300'
  tag cci: ["CCI-003376"]
  tag nist: ["SA-22 a"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW server_version;', [conn.db]) do
    its('output.strip') { should match(/\A\d+(\.\d+)*/) }
  end

  describe 'Manually verify against the current PostgreSQL / Crunchy Data support lifecycle that the running major version (reported above) is still vendor-supported.' do
    skip 'Manually verify against the current PostgreSQL / Crunchy Data support lifecycle that the running major version (reported above) is still vendor-supported.'
  end
end
