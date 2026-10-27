control 'V-261873' do
  title 'PostgreSQL must, by default, shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'check', <<~EOT
    If the application owner has determined that the need for system availability outweighs the need for a complete audit trail, this is Not Applicable.

    Review the procedures, either manually and/or automated, for monitoring the space used by audit trail(s) and for offloading audit records to a centralized log management system.

    If the procedures do not exist, this is a finding.

    If the procedures exist, request evidence that they are followed. If the evidence indicates that the procedures are not followed, this is a finding.

    If the procedures exist, inquire if the system has ever run out of audit trail space in the last two years or since the last system upgrade, whichever is more recent. If it has run out of space in this period, and the procedures have not been updated to compensate, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Modify PostgreSQL, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag gid: 'V-261873'
  tag rid: 'SV-261873r1043188_rule'
  tag stig_id: 'CD16-00-001700'
  tag cci: ["CCI-000140"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
