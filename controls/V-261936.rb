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
  tag nist: ["SI-2 c"]
  aws_ready = command('aws').exist?
  only_if('The AWS CLI must be installed and configured with credentials, and the aws_db_instance_identifier input must be set, to evaluate this control.') do
    aws_ready && !input('aws_db_instance_identifier').empty?
  end

  region_flag = input('aws_region').empty? ? '' : "--region #{input('aws_region')}"
  profile_flag = input('aws_cli_profile').empty? ? '' : "--profile #{input('aws_cli_profile')}"

  describe command("aws rds describe-db-instances --db-instance-identifier #{input('aws_db_instance_identifier')} #{region_flag} #{profile_flag} --query 'DBInstances[0].[EngineVersion,AutoMinorVersionUpgrade]' --output text") do
    its('exit_status') { should eq 0 }
  end

  # Filter server-side by instance: the ResourceIdentifier field in the response is the
  # instance ARN, so filtering it client-side against the bare identifier never matched.
  pending_cmd = "aws rds describe-pending-maintenance-actions --filters Name=db-instance-id,Values=#{input('aws_db_instance_identifier')} #{region_flag} #{profile_flag} --query 'PendingMaintenanceActions' --output json"
  describe command(pending_cmd) do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should cmp '[]' }
  end
end
