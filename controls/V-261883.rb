control 'V-261883' do
  title 'Database software, including PostgreSQL configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.'
  desc 'check', <<~EOT
    Review the PostgreSQL software library directory and any subdirectories.

    If any non-PostgreSQL software directories exist on the disk directory, examine or investigate their use. If any of the directories are used by other applications, including third-party applications that use the PostgreSQL, this is a finding.

    Only applications that are required for the functioning and administration, not use, of the PostgreSQL software library should be located in the same disk directory as the PostgreSQL software libraries.

    If other applications are located in the same directory as PostgreSQL, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Install all applications on directories separate from the PostgreSQL software library directory. Relocate any directories or reinstall other application software that currently shares the PostgreSQL software library directory.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag gid: 'V-261883'
  tag rid: 'SV-261883r1000654_rule'
  tag stig_id: 'CD16-00-002800'
  tag cci: ["CCI-001499"]
  tag nist: []
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/removal of PostgreSQL engine binaries and packages for RDS-hosted instances. Customers do not have OS-level or package-manager access required to evaluate this control; engine version and patch status are instead verified via the AWS RDS API (see related controls).'
  end
end
