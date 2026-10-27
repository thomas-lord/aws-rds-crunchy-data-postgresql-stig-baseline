control 'V-261925' do
  title 'PostgreSQL must produce audit records of its enforcement of access restrictions associated with changes to the configuration of PostgreSQL or database(s).'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    To verify that system denies are logged when unprivileged users attempt to change database configuration, as the database administrator (shown here as "postgres"), run the following commands:

    $ sudo su - postgres
    $ psql

    Create a role with no privileges, change the current role to that user, and attempt to change a configuration by running the following SQL:

    CREATE ROLE bob;
    SET ROLE bob;
    SET pgaudit.role='test';
    RESET ROLE;
    DROP ROLE bob;

    Check ${PGLOG?} (use the latest log):

    $ cat ${PGDATA?}/${PGLOG?}/postgresql-Thu.log
    < 2024-01-28 17:57:34.092 UTC bob postgres: >ERROR: permission denied to set parameter "pgaudit.role"
    < 2024-01-28 17:57:34.092 UTC bob postgres: >STATEMENT: SET pgaudit.role='test';

    If the denial is not logged, this is a finding.

    By default PostgreSQL configuration files are owned by the Postgres user and cannot be edited by nonprivileged users:

    $ ls -la ${PGDATA?} | grep postgresql.conf
    -rw-------. 1 postgres postgres 21758 Jan 22 10:27 postgresql.conf

    If postgresql.conf is not owned by the database owner and does not have read and write permissions for the owner, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Enable logging.

    All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag gid: 'V-261925'
  tag rid: 'SV-261925r1000780_rule'
  tag stig_id: 'CD16-00-007900'
  tag cci: ["CCI-001814"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
