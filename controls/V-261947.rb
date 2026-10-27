control 'V-261947' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), create a test role by running the following SQL:

    $ sudo su - postgres
    $ psql -c "CREATE ROLE bob"

    To test if audit records are generated from unsuccessful attempts at modifying security objects, run the following SQL:

    $ sudo su - postgres
    $ psql -c "SET ROLE bob; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';"

    As the database administrator (shown here as "postgres"), verify the denials were logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    < 2024-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >ERROR: permission denied for relation pg_authid
    < 2024-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >STATEMENT: UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';

    If denials are not logged, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to produce audit records when unsuccessful attempts to modify security objects occur.

    Unsuccessful attempts to modify security objects can be logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag gid: 'V-261947'
  tag rid: 'SV-261947r1000846_rule'
  tag stig_id: 'CD16-00-010300'
  tag cci: ["CCI-000172"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
