control 'V-261888' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'check', <<~EOT
    PostgreSQL's COPY command can interact with the underlying OS. Only superuser has access to this command.

    As the database administrator (shown here as "postgres"), run the following SQL to list all roles and their privileges:

    $ sudo su - postgres
    $ psql -x -c "\du"

    If any role has "superuser" that should not, this is a finding.

    It is possible for an extension to contain code that could access external executables via SQL. To list all installed extensions, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -x -c "SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL"

    If any installed extensions are not approved, this is a finding.
  EOT
  desc 'fix', <<~EOT
    To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"

    To remove extensions from PostgreSQL, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "DROP EXTENSION extension_name"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag gid: 'V-261888'
  tag rid: 'SV-261888r1000669_rule'
  tag stig_id: 'CD16-00-003400'
  tag cci: ["CCI-000381"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
