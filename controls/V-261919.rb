control 'V-261919' do
  title 'PostgreSQL must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'check', <<~EOT
    Review system configuration.

    If no script or tool is monitoring the partition for the PostgreSQL log directories, this is a finding.

    If appropriate support staff are not notified immediately upon storage volume utilization reaching 75 percent, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75 percent.

    PostgreSQL does not monitor storage; however, it is possible to monitor storage with a script.

    ##### Example Monitoring Script

    #!/bin/bash

    PGDATA=/var/lib/pgsql/${PGVER?}/data
    CURRENT=$(df ${PGDATA?} | grep / | awk '{ print $5}' | sed 's/%//g')
    THRESHOLD=75

    if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
    mail -s 'Disk Space Alert' mail@support.com << EOF
    The data directory volume is almost full. Used: $CURRENT
    EOF
    fi

    Schedule this script in cron to run around the clock.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag gid: 'V-261919'
  tag rid: 'SV-261919r1000762_rule'
  tag stig_id: 'CD16-00-007300'
  tag cci: ["CCI-001855"]
  tag nist: []
  aws_ready = command('aws').exist?
  only_if('The AWS CLI must be installed and configured with credentials, and the aws_db_instance_identifier input must be set, to evaluate this control.') do
    aws_ready && !input('aws_db_instance_identifier').empty?
  end

  region_flag = input('aws_region').empty? ? '' : "--region #{input('aws_region')}"
  profile_flag = input('aws_cli_profile').empty? ? '' : "--profile #{input('aws_cli_profile')}"

  alarms_cmd = "aws cloudwatch describe-alarms-for-metric --namespace AWS/RDS --metric-name FreeStorageSpace --dimensions Name=DBInstanceIdentifier,Value=#{input('aws_db_instance_identifier')} #{region_flag} #{profile_flag} --query 'MetricAlarms' --output json"
  describe command(alarms_cmd) do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should_not cmp '[]' }
  end

  describe "Manually verify that the CloudWatch alarm(s) listed above (or an equivalent mechanism) notify appropriate support staff once free storage drops below the organization-defined threshold (default #{input('pg_storage_alarm_threshold_percent')} percent utilized)." do
    skip "Manually verify that the CloudWatch alarm(s) listed above (or an equivalent mechanism) notify appropriate support staff once free storage drops below the organization-defined threshold (default #{input('pg_storage_alarm_threshold_percent')} percent utilized)."
  end
end
