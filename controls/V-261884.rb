control 'V-261884' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/PostgreSQL principals authorized for ownership.'
  desc 'check', <<~EOT
    Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).

    If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

    To check the ownership of objects in the database, as the database administrator, run the following SQL:

    $ sudo su - postgres
    $ psql -X -c '\dnS'
    $ psql -x -c "\dt *.*"
    $ psql -X -c '\dsS'
    $ psql -x -c "\dv *.*"
    $ psql -x -c "\df+ *.*"

    If any object is not owned by an authorized role for ownership, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Assign ownership of authorized objects to authorized object owner accounts.

    #### Schema Owner

    To create a schema owned by the user "bob", run the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE SCHEMA test AUTHORIZATION bob" 

    To alter the ownership of an existing object to be owned by the user "bob", run the following SQL:

    $ sudo su - postgres
    $ psql -c "ALTER SCHEMA test OWNER TO bob"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: 'V-261884'
  tag rid: 'SV-261884r1000657_rule'
  tag stig_id: 'CD16-00-002900'
  tag cci: ["CCI-001499"]
  tag nist: ["CM-5 (6)"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
