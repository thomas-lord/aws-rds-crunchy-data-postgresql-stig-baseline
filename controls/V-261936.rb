control 'V-261936' do
  title 'Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', <<~EOT
    If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:

    To list the version of installed PostgreSQL using psql:

    $ sudo su - postgres
    $ psql --version

    To list the current version of software for RPM:

    $ rpm -qa | grep postgres

    To list the current version of software for APT:

    $ apt-cache policy postgres

    All versions of PostgreSQL are listed here: http://www.postgresql.org/support/versioning/.

    All security-relevant software updates for PostgreSQL are listed here: http://www.postgresql.org/support/security/.

    If PostgreSQL is not at the latest version, this is a finding.

    If PostgreSQL is not at the latest version and the evaluated version has CVEs (IAVAs), then this is a CAT I finding.
  EOT
  desc 'fix', <<~EOT
    Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag gid: 'V-261936'
  tag rid: 'SV-261936r1137667_rule'
  tag stig_id: 'CD16-00-009200'
  tag cci: ["CCI-002605"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
