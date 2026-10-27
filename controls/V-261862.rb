control 'V-261862' do
  title 'PostgreSQL must allow only the information system security manager (ISSM), or individuals or roles appointed by the ISSM, to select which events are to be audited.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Check PostgreSQL settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.

    As the database administrator (shown here as "postgres"), verify the permissions for PGDATA:

    $ ls -la ${PGDATA?}

    If anything in PGDATA is not owned by the database administrator, this is a finding.

    As the database administrator, run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    Review the role permissions, if any role is listed as superuser but should not have that access, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL's settings to allow designated personnel to select which auditable events are audited.

    Using pgaudit allows administrators the flexibility to choose what they log. For an overview of the capabilities of pgaudit, refer to https://github.com/pgaudit/pgaudit. 

    Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

    Refer to supplementary content APPENDIX-C for instructions on enabling logging. Only administrators/superuser can change PostgreSQL configurations. Access to the database administrator must be limited to designated personnel only.

    To ensure that postgresql.conf is owned by the database owner:

    $ chown postgres:postgres ${PGDATA?}/postgresql.conf
    $ chmod 600 ${PGDATA?}/postgresql.conf
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag gid: 'V-261862'
  tag rid: 'SV-261862r1000591_rule'
  tag stig_id: 'CD16-00-000600'
  tag cci: ["CCI-000171"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
