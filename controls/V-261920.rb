control 'V-261920' do
  title 'PostgreSQL must provide an immediate real-time alert to appropriate support staff of all audit log failures.'
  desc 'check', <<~EOT
    Review PostgreSQL, OS, or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

    If real-time alerts are not sent upon auditing failure, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure the system to provide an immediate real-time alert to appropriate support staff when an audit log failure occurs.

    It is possible to create scripts or implement third-party tools to enable real-time alerting for audit failures in PostgreSQL.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag gid: 'V-261920'
  tag rid: 'SV-261920r1000973_rule'
  tag stig_id: 'CD16-00-007400'
  tag cci: ["CCI-001858"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
