control 'V-261882' do
  title 'The PostgreSQL software installation account must be restricted to authorized users.'
  desc <<~EOT
    When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system.

    If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications.

    DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on database security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them.
  EOT
  desc 'check', <<~EOT
    Review procedures for controlling, granting access to, and tracking use of the PostgreSQL software installation account(s).

    If access or use of this account is not restricted to the minimum number of personnel required or if unauthorized access to the account has been granted, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Develop, document, and implement procedures to restrict and track use of the PostgreSQL software installation account(s).
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag gid: 'V-261882'
  tag rid: 'SV-261882r1000651_rule'
  tag stig_id: 'CD16-00-002700'
  tag cci: ["CCI-001499"]
  tag nist: ["CM-5 (6)"]
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).'
  end
end
