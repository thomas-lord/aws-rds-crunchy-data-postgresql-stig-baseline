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

  describe 'CloudWatch alarms on the instance FreeStorageSpace metric' do
    subject { conn.free_storage_alarms.map { |alarm| alarm['AlarmName'] } }
    it { should_not be_empty }
  end

  # Build the message outside the describe block: inside one, `input` defines an
  # RSpec example rather than returning the input's value.
  manual_note = "Manually verify that the CloudWatch alarm(s) listed above (or an equivalent mechanism) notify appropriate support staff once free storage drops below the organization-defined threshold (default #{input('pg_storage_alarm_threshold_percent')} percent utilized)."
  describe manual_note do
    skip manual_note
  end
end
