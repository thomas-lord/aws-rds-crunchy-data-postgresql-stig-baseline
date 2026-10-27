control 'V-261918' do
  title 'PostgreSQL must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'check', <<~EOT
    Investigate whether there have been any incidents where PostgreSQL ran out of audit log space since the last time the space was allocated or other corrective measures were taken.

    If there have been incidents where PostgreSQL ran out of audit log space, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Allocate sufficient audit file/table space to support peak demand.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag gid: 'V-261918'
  tag rid: 'SV-261918r1000759_rule'
  tag stig_id: 'CD16-00-007200'
  tag cci: ["CCI-001849"]
  tag nist: ["AU-4"]
  aws_ready = command('aws').exist?
  only_if('The AWS CLI must be installed and configured with credentials, and the aws_db_instance_identifier input must be set, to evaluate this control.') do
    aws_ready && !input('aws_db_instance_identifier').empty?
  end

  region_flag = input('aws_region').empty? ? '' : "--region #{input('aws_region')}"
  profile_flag = input('aws_cli_profile').empty? ? '' : "--profile #{input('aws_cli_profile')}"

  describe command("aws rds describe-db-instances --db-instance-identifier #{input('aws_db_instance_identifier')} #{region_flag} #{profile_flag} --query 'DBInstances[0].[AllocatedStorage,MaxAllocatedStorage]' --output text") do
    its('stdout.split') { should_not be_empty }
    its('exit_status') { should eq 0 }
  end

  describe 'Verify (from the AllocatedStorage/MaxAllocatedStorage values reported above) that RDS Storage Autoscaling is configured with headroom sufficient for the organization-defined audit record storage requirement.' do
    skip 'Verify (from the AllocatedStorage/MaxAllocatedStorage values reported above) that RDS Storage Autoscaling is configured with headroom sufficient for the organization-defined audit record storage requirement.'
  end
end
