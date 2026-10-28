control 'V-261911' do
  title 'PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in storage.'
  desc 'check', <<~EOT
    If security labeling is not required, this is not a finding.

    As the database administrator (shown here as "postgres"), run the following SQL against each table that requires security labels:

    $ sudo su - postgres
    $ psql -c "\d+ <schema_name>.<table_name>"

    If security labeling is required and the results of the SQL above do not show a policy attached to the table, this is a finding.

    If security labeling is required and not implemented according to the system documentation, such as SSP, this is a finding.

    If security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in storage, this is a finding.
  EOT
  desc 'fix', <<~EOT
    In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

    RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag gid: 'V-261911'
  tag rid: 'SV-261911r1138540_rule'
  tag stig_id: 'CD16-00-006400'
  tag cci: ["CCI-002262"]
  tag nist: ["AC-16 a"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
