control 'V-261874' do
  title 'PostgreSQL must be configurable to overwrite audit log records, oldest first (first-in-first-out [FIFO]), in the event of unavailability of space for more audit log records.'
  desc 'check', <<~EOT
    If the Authorizing Official (AO)-approved system documentation states that system availability takes precedence, this requirement is Not Applicable.

    If an externally managed and monitored partition or logical volume that can be grown dynamically is being used for logging, this is not a finding. 

    If PostgreSQL is auditing to a directory that is not being actively checked for availability of disk space, and if a tool, utility, script, or other mechanism is not being used to ensure sufficient disk space is available for the creation of new audit logs, this is a finding.

    If a tool, utility, script, or other mechanism is being used to rotate audit logs and oldest logs are not being removed to ensure sufficient space for newest logs or oldest logs are not being replaced by newest logs, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Establish a process with accompanying tools for monitoring available disk space and ensuring that sufficient disk space is maintained to continue generating audit logs, overwriting the oldest existing records if necessary.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag gid: 'V-261874'
  tag rid: 'SV-261874r1043188_rule'
  tag stig_id: 'CD16-00-001800'
  tag cci: ["CCI-000140"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
