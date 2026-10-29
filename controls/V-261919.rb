control 'V-261919' do
  title 'PostgreSQL must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc <<~EOT
    Organizations are required to use a central log management system so under normal conditions, the audit space allocated to PostgreSQL on its own server will not be an issue. However, space will still be required on the PostgreSQL server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

    If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

    The appropriate support staff include, at a minimum, the information system security officer (ISSO) and the database administrator (DBA)/system administrator (SA).
  EOT
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
  tag nist: ["AU-5 (1)"]
  conn = rds_connection
  rds_only_if_aws(conn)

  # The STIG wants support staff warned once storage is threshold-percent used (75 by
  # default). An alarm counts if it has actions enabled and at least one action (e.g. an
  # SNS topic), and fires while free storage is at or above (100 - threshold) percent of the
  # allocated storage.
  threshold_percent = input('pg_storage_alarm_threshold_percent').to_f
  checks = [
    rds_check("CloudWatch alarms on FreeStorageSpace that notify someone by #{threshold_percent.round}% used") do
      min_free_bytes = conn.aws_instance_attr('AllocatedStorage').to_f * (1024**3) * (100 - threshold_percent) / 100
      alarms = conn.free_storage_alarms
      notifying = alarms.select do |alarm|
        alarm['ActionsEnabled'] && !Array(alarm['AlarmActions']).empty? &&
          %w[LessThanThreshold LessThanOrEqualToThreshold].include?(alarm['ComparisonOperator']) &&
          alarm['Threshold'].to_f >= min_free_bytes
      end
      others = alarms.map { |alarm| alarm['AlarmName'] } - notifying.map { |alarm| alarm['AlarmName'] }
      [!notifying.empty?, "#{notifying.empty? ? 'none' : notifying.map { |alarm| alarm['AlarmName'] }.join(', ')}" \
                          "#{others.empty? ? '' : "; not counted (no actions, or threshold too low): #{others.join(', ')}"}"]
    end
  ]
  manual_note = 'Manually verify that the alarm actions listed above (e.g. SNS topic subscriptions) reach appropriate support staff, at a minimum the ISSO and the DBA/SA.'
  rds_review_results(checks, manual_note).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
