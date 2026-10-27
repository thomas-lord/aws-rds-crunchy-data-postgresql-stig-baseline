control 'V-261887' do
  title 'Unused database components that are integrated in PostgreSQL and cannot be uninstalled must be disabled.'
  desc 'check', <<~EOT
    To list all installed packages, as the system administrator, run the following:

    # RHEL/CENT 8/9 Systems
    $ sudo dnf list installed | grep postgres

    # RHEL/CENT 7 Systems
    $ sudo yum list installed | grep postgres

    # Debian Systems
    $ dpkg --get-selections | grep postgres

    If any of the packages installed not required, this is a finding.
  EOT
  desc 'fix', <<~EOT
    To remove any unneeded executables, as the system administrator, run the following:

    # RHEL/CENT Systems
    $ sudo yum erase <package_name>

    # Debian Systems
    $ sudo apt-get remove <package_name>
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag gid: 'V-261887'
  tag rid: 'SV-261887r1000666_rule'
  tag stig_id: 'CD16-00-003300'
  tag cci: ["CCI-000381"]
  tag nist: []
  impact 0.0
  describe 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/patching of the PostgreSQL engine for RDS-hosted instances. Customers do not have OS-level or file-system access required to evaluate this control.' do
    skip 'This control is not applicable: AWS manages the underlying operating system, file system, and installation/patching of the PostgreSQL engine for RDS-hosted instances. Customers do not have OS-level or file-system access required to evaluate this control.'
  end
end
