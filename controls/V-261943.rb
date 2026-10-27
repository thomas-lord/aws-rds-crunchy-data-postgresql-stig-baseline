control 'V-261943' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create a role "bob" and a test table by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE bob; CREATE TABLE test(id INT);"

    Set current role to "bob" and attempt to modify privileges:

    $ psql -c "SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;"

    As the database administrator (shown here as "postgres"), verify the unsuccessful attempt was logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    2024-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test
    2024-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob;

    If audit logs are not generated when unsuccessful attempts to add privileges/permissions occur, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to add privileges occur.

    All denials are logged by default if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag gid: 'V-261943'
  tag rid: 'SV-261943r1000834_rule'
  tag stig_id: 'CD16-00-009900'
  tag cci: ["CCI-000172"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
