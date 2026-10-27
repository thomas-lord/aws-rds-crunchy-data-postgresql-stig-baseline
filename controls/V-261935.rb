control 'V-261935' do
  title 'When updates are applied to the PostgreSQL software, any software components that have been replaced or made unnecessary must be removed.'
  desc 'check', <<~EOT
    To check software installed by packages, as the system administrator, run the following command:

    $ sudo rpm -qa | grep postgres

    If multiple versions of postgres are installed but are unused, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag gid: 'V-261935'
  tag rid: 'SV-261935r1000810_rule'
  tag stig_id: 'CD16-00-009100'
  tag cci: ["CCI-002617"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
