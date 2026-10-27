control 'V-261905' do
  title 'PostgreSQL must check the validity of all data inputs except those specifically identified by the organization.'
  desc 'check', <<~EOT
    Review PostgreSQL code (trigger procedures, functions), application code, settings, column and field definitions, and constraints to determine whether the database is protected against invalid input.

    If code exists that allows invalid data to be acted upon or input into the database, this is a finding.

    If column/field definitions do not exist in the database, this is a finding.

    If columns/fields do not contain constraints and validity checking where required, this is a finding.

    Where a column/field is noted in the system documentation as necessarily free-form, even though its name and context suggest that it should be strongly typed and constrained, the absence of these protections is not a finding.

    Where a column/field is clearly identified by name, caption or context as Notes, Comments, Description, Text, etc., the absence of these protections is not a finding.

    Check application code that interacts with PostgreSQL for the use of prepared statements. If prepared statements are not used, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Modify database code to properly validate data before it is put into the database or acted upon by the database.

    Modify the database to contain constraints and validity checking on database columns and tables that require them for data integrity.

    Use prepared statements when taking user input.

    Do not allow general users direct console access to PostgreSQL.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag gid: 'V-261905'
  tag rid: 'SV-261905r1000720_rule'
  tag stig_id: 'CD16-00-005700'
  tag cci: ["CCI-001310"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
