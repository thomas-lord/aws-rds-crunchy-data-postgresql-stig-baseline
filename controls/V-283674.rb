control 'V-283674' do
  title 'PostgreSQL products must be a version supported by the vendor.'
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

  describe sql.query('SHOW server_version;', [conn.db]) do
    its('output') { should_not be_empty }
  end

  describe 'Manually verify against the current PostgreSQL / Crunchy Data support lifecycle that the running major version (reported above) is still vendor-supported.' do
    skip 'Manually verify against the current PostgreSQL / Crunchy Data support lifecycle that the running major version (reported above) is still vendor-supported.'
  end
end
