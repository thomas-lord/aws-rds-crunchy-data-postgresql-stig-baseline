control 'V-261907' do
  title 'PostgreSQL and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.'
  desc 'check', <<~EOT
    Review PostgreSQL source code (trigger procedures, functions) and application source code to identify cases of dynamic code execution.

    If dynamic code execution is employed without protective measures against code injection, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Where dynamic code execution is used, modify the code to implement protections against code injection (i.e., prepared statements).
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-DB-000392'
  tag gid: 'V-261907'
  tag rid: 'SV-261907r1000726_rule'
  tag stig_id: 'CD16-00-005900'
  tag cci: ["CCI-001310"]
  tag nist: ["SI-10"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
