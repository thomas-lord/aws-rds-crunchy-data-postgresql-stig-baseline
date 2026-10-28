control 'V-261886' do
  title 'Unused database components, PostgreSQL software, and database objects must be removed.'
  desc <<~EOT
    Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

    PostgreSQL must adhere to the principles of least functionality by providing only essential capabilities.
  EOT
  desc 'check', <<~EOT
    To get a list of all extensions installed, use the following commands:

    $ sudo su - postgres
    $ psql -c "select * from pg_extension where extname != 'plpgsql'"

    If any extensions exist that are not approved, this is a finding.
  EOT
  desc 'fix', <<~EOT
    To remove extensions, use the following commands:

    $ sudo su - postgres
    $ psql -c "DROP EXTENSION <extension_name>"

    Note: Removal of plpgsql is not recommended.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag gid: 'V-261886'
  tag rid: 'SV-261886r1000951_rule'
  tag stig_id: 'CD16-00-003200'
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
