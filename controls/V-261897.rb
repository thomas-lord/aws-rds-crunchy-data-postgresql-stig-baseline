control 'V-261897' do
  title 'PostgreSQL must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).'
  desc 'check', <<~EOT
    PostgreSQL uniquely identifies and authenticates PostgreSQL users through the use of DBMS roles.

    To list all roles in the database, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    If users are not uniquely identified per organizational documentation, this is a finding.
  EOT
  desc 'fix', <<~EOT
    To drop a role, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "DROP ROLE <role_to_drop>"

    To create a role, as the database administrator, run the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE <role name> LOGIN"

    For the complete list of permissions allowed by roles, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag gid: 'V-261897'
  tag rid: 'SV-261897r1000696_rule'
  tag stig_id: 'CD16-00-004500'
  tag cci: ["CCI-000804"]
  tag nist: ["IA-8"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
