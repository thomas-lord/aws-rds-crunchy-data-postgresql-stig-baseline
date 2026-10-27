control 'V-261903' do
  title 'Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.'
  desc 'check', <<~EOT
    Review the procedures for the refreshing of development/test data from production.

    Review any scripts or code that exists for the movement of production data to development/test systems, or to any other location or for any other purpose.

    Verify that copies of production data are not left in unprotected locations. 

    If the code that exists for data movement does not comply with the organization-defined data transfer policy and/or fails to remove any copies of production data from unprotected locations, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag gid: 'V-261903'
  tag rid: 'SV-261903r1137656_rule'
  tag stig_id: 'CD16-00-005400'
  tag cci: ["CCI-001090"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
