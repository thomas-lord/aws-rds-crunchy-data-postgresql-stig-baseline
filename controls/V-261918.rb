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
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
