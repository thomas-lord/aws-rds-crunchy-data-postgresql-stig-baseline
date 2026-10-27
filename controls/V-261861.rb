control 'V-261861' do
  title 'PostgreSQL must provide audit record generation capability for DOD-defined auditable events within all DBMS/database components.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGLOG environment variables. Refer to supplementary content APPENDIX-I for instructions on configuring PGVER.

    Check PostgreSQL audit logs to determine whether organization-defined auditable events are being audited by the system.

    For example, if the organization defines 'CREATE TABLE' as an auditable event, issuing the following command should return a result:

    $ sudo su - postgres
    $ psql -c "CREATE TABLE example (id int)"
    $ grep 'AUDIT:.*,CREATE TABLE.*example' ${PGLOG?}/<latest_log>
    $ psql -c 'DROP TABLE example;'

    If organization-defined auditable events are not being audited, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to generate audit records for at least the DOD minimum set of events.

    Using "pgaudit", PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-261861'
  tag rid: 'SV-261861r1000588_rule'
  tag stig_id: 'CD16-00-000500'
  tag cci: ["CCI-000169"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
