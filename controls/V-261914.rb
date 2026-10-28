control 'V-261914' do
  title 'PostgreSQL must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'check', <<~EOT
    Review system documentation to identify the required discretionary access control (DAC).

    Review the security configuration of the database and PostgreSQL. If applicable, review the security configuration of the application(s) using the database.

    If the discretionary access control defined in the documentation is not implemented in the security configuration, this is a finding.

    If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

    To check the ownership of objects in the database, as the database administrator, run the following:

    $ sudo su - postgres
    $ psql -X -c '\dnS'
    $ psql -x -c "\dt *.*"
    $ psql -X -c '\dsS'
    $ psql -x -c "\dv *.*"
    $ psql -x -c "\df+ *.*"

    If any role is given privileges to objects it should not have, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Implement the organization's DAC policy in the security configuration of the database and PostgreSQL, and, if applicable, the security configuration of the application(s) using the database.

    To GRANT privileges to roles, as the database administrator (shown here as "postgres"), run statements like the following examples:

    $ sudo su - postgres
    $ psql -c "CREATE SCHEMA test"
    $ psql -c "GRANT CREATE ON SCHEMA test TO bob"
    $ psql -c "CREATE TABLE test.test_table(id INT)"
    $ psql -c "GRANT SELECT ON TABLE test.test_table TO bob"

    To REVOKE privileges to roles, as the database administrator (shown here as "postgres"), run statements like the following examples:

    $ psql -c "REVOKE SELECT ON TABLE test.test_table FROM bob"
    $ psql -c "REVOKE CREATE ON SCHEMA test FROM bob"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag gid: 'V-261914'
  tag rid: 'SV-261914r1000747_rule'
  tag stig_id: 'CD16-00-006700'
  tag cci: ["CCI-002165"]
  tag nist: ["AC-3 (4)"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
