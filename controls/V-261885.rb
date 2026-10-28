control 'V-261885' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to PostgreSQL, etc.) must be restricted to authorized users.'
  desc <<~EOT
    If PostgreSQL were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    As the database administrator (shown here as "postgres"), list all users and their permissions by running the following SQL:

    $ sudo su - postgres
    $ psql -c "\dp *.*"

    Verify that all objects have the correct privileges. If they do not, this is a finding.

    As the database administrator (shown here as "postgres"), verify the permissions of the database directory on the filesystem:

    $ ls -la ${PGDATA?}

    If permissions of the database directory are not limited to an authorized user account, this is a finding.
  EOT
  desc 'fix', <<~EOT
    As the database administrator, revoke any permissions from a role that are deemed unnecessary by running the following SQL:

    ALTER ROLE bob NOCREATEDB;
    ALTER ROLE bob NOCREATEROLE;
    ALTER ROLE bob NOSUPERUSER;
    ALTER ROLE bob NOINHERIT;
    REVOKE SELECT ON some_function FROM bob;
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag gid: 'V-261885'
  tag rid: 'SV-261885r1000949_rule'
  tag stig_id: 'CD16-00-003000'
  tag cci: ["CCI-001499"]
  tag nist: ["CM-5 (6)"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
