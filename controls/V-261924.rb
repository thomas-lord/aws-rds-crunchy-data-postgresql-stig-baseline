control 'V-261924' do
  title 'PostgreSQL must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'check', <<~EOT
    To list all the permissions of individual roles, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    If any role has SUPERUSER that should not, this is a finding.

    List all the permissions of databases and schemas by running the following SQL:

    $ sudo su - postgres
    $ psql -c "\l"
    $ psql -c "\dn+"

    If any database or schema has update ("W") or create ("C") privileges and should not, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

    Use ALTER ROLE to remove accesses from roles:

    $ psql -c "ALTER ROLE <role_name> NOSUPERUSER"

    Use REVOKE to remove privileges from databases and schemas:

    $ psql -c "REVOKE ALL PRIVILEGES ON <table> FROM <role_name>"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag gid: 'V-261924'
  tag rid: 'SV-261924r1000777_rule'
  tag stig_id: 'CD16-00-007800'
  tag cci: ["CCI-001813"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
