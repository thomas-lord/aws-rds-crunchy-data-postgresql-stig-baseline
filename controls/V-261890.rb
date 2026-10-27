control 'V-261890' do
  title 'PostgreSQL must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'check', <<~EOT
    Review PostgreSQL settings to determine whether organizational users are uniquely identified and authenticated when logging on/connecting to the system.

    To list all roles in the database, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    If organizational users are not uniquely identified and authenticated, this is a finding.

    As the database administrator (shown here as "postgres"), verify the current pg_hba.conf authentication settings:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_hba.conf

    If every role does not have unique authentication requirements, this is a finding.

    If accounts are determined to be shared, determine if individuals are first individually authenticated. If individuals are not individually authenticated before using the shared account, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Configure PostgreSQL settings to uniquely identify and authenticate all organizational users who log on/connect to the system.

    To create roles, use the following SQL:

    CREATE ROLE <role_name> [OPTIONS]

    For more information on CREATE ROLE, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html.

    For each role created, the database administrator can specify database authentication by editing pg_hba.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/pg_hba.conf

    An example pg_hba entry looks like this:

    # TYPE DATABASE USER ADDRESS METHOD
    host test_db bob 192.168.0.0/16 scram-sha-256

    For more information on pg_hba.conf, refer to the official documentation: https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag gid: 'V-261890'
  tag rid: 'SV-261890r1051115_rule'
  tag stig_id: 'CD16-00-003600'
  tag cci: ["CCI-000764"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
