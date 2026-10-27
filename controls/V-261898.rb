control 'V-261898' do
  title 'PostgreSQL must separate user functionality (including user interface services) from database management functionality.'
  desc 'check', <<~EOT
    Check PostgreSQL settings and vendor documentation to verify that administrative functionality is separate from user functionality.

    As the database administrator (shown here as "postgres"), list all roles and permissions for the database:

    $ sudo su - postgres
    $ psql -c "\du"

    If any nonadministrative role has the attribute "Superuser", "Create role", "Create DB" or "Bypass RLS", this is a finding.

    If administrator and general user functionality are not separated either physically or logically, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to separate database administration and general user functionality.

    Do not grant superuser, create role, create db, or bypass rls role attributes to users that do not require it.

    To remove privileges, refer to the following example:

    ALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag gid: 'V-261898'
  tag rid: 'SV-261898r1137655_rule'
  tag stig_id: 'CD16-00-004600'
  tag cci: ["CCI-001082"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
