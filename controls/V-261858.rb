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
  aws_ready = command('aws').exist?
  only_if('The AWS CLI must be installed and configured with credentials, and the aws_db_instance_identifier input must be set, to evaluate this control.') do
    aws_ready && !input('aws_db_instance_identifier').empty?
  end

  region_flag = input('aws_region').empty? ? '' : "--region #{input('aws_region')}"
  profile_flag = input('aws_cli_profile').empty? ? '' : "--profile #{input('aws_cli_profile')}"

  describe command("aws rds describe-db-instances --db-instance-identifier #{input('aws_db_instance_identifier')} #{region_flag} #{profile_flag} --query 'DBInstances[0].IAMDatabaseAuthenticationEnabled' --output text") do
    its('stdout.strip') { should cmp 'True' }
    its('exit_status') { should eq 0 }
  end

  describe 'If the organization instead uses Kerberos/Active Directory authentication for this instance (DomainMemberships), manually verify that via `aws rds describe-db-instances` rather than IAM database authentication.' do
    skip 'If the organization instead uses Kerberos/Active Directory authentication for this instance (DomainMemberships), manually verify that via `aws rds describe-db-instances` rather than IAM database authentication.'
  end
end
