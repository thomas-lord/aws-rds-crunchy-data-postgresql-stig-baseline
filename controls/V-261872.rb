control 'V-261872' do
  title 'PostgreSQL must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F and APPENDIX-I for instructions on configuring them.

    Review the system documentation to identify what additional information the organization has determined necessary.

    Check PostgreSQL settings by examining ${PGDATA?}/postgresql.conf to ensure additional auditing is configured and then examine existing audit records in ${PGLOG?}/<latest.log> to verify that all organization-defined additional, more detailed information is in the audit records for audit events identified by type, location, or subject after executing SQL commands that fall under the additional audit classes.

    If any additional information is defined and is not contained in the audit records, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL audit settings to include all organization-defined detailed information in the audit records for audit events identified by type, location, or subject.

    Using pgaudit, PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag gid: 'V-261872'
  tag rid: 'SV-261872r1000621_rule'
  tag stig_id: 'CD16-00-001600'
  tag cci: ["CCI-000135"]
  tag nist: ["AU-3 (1)"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
