control 'V-261935' do
  title 'When updates are applied to the PostgreSQL software, any software components that have been replaced or made unnecessary must be removed.'
  desc 'check', <<~EOT
    To check software installed by packages, as the system administrator, run the following command:

    $ sudo rpm -qa | grep postgres

    If multiple versions of postgres are installed but are unused, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag gid: 'V-261935'
  tag rid: 'SV-261935r1000810_rule'
  tag stig_id: 'CD16-00-009100'
  tag cci: ["CCI-002617"]
  tag nist: []
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).'
  end
end
