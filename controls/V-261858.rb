control 'V-261858' do
  title 'PostgreSQL must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    If all accounts are authenticated by the organization-level authentication/access mechanism, such as LDAP or Kerberos and not by PostgreSQL, this is not a finding.

    As the database administrator (shown here as "postgres"), review pg_hba.conf authentication file settings:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_hba.conf

    All records must use an auth-method of gss, sspi, ldap, or cert. For details on the specifics of these authentication methods refer to: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html.

    If there are any records with a different auth-method than gss, sspi, ldap, or cert, review the system documentation for justification and approval of these records.

    If there are any records with a different auth-method than gss, sspi, ldap, or cert, that are not documented and approved, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Integrate PostgreSQL security with an organization-level authentication/access mechanism providing account management for all users, groups, roles, and any other principals.

    As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file:

    $ sudo su - postgres
    $ vi ${PGDATA?}/pg_hba.conf

    For each PostgreSQL-managed account that is not documented and approved, either transfer it to management by the external mechanism, or document the need for it and obtain approval, as appropriate.
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag gid: 'V-261858'
  tag rid: 'SV-261858r1043176_rule'
  tag stig_id: 'CD16-00-000200'
  tag cci: ["CCI-000015"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
