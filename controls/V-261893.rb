control 'V-261893' do
  title 'PostgreSQL, when using PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc <<~EOT
    The DOD standard for authentication is DOD-approved PKI certificates.

    A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

    Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    To verify that a CRL file exists, as the database administrator (shown here as "postgres"), run the following:

    $ sudo su - postgres
    $ psql -c "SELECT CASE WHEN length(setting) > 0 
    THEN CASE WHEN substring(setting, 1, 1) = '/' 
    THEN setting 
    ELSE (SELECT setting FROM pg_settings WHERE name = 'data_directory') || '/' || setting
    END
    ELSE ''
    END AS ssl_crl_file
    FROM pg_settings
    WHERE name = 'ssl_crl_file';"

    If this is not set to a CRL file, this is a finding.

    Verify the existence of the CRL file by checking the directory from above:

    $ sudo su - postgres
    $ ls -ld <ssl_crl_file>

    If the CRL file does not exist, this is a finding.

    Verify that hostssl entries in pg_hba.conf have "cert" and "clientcert=verify-ca" enabled:

    $ sudo su - postgres
    $ grep '^hostssl.*cert.*clientcert=verify-ca ' ${PGDATA?}/pg_hba.conf

    If hostssl entries are not returned, this is a finding.

    If certificates are not being validated by performing RFC 5280-compliant certification path validation, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

    To generate a Certificate Revocation List, refer to the official Red Hat Documentation: https://access.redhat.com/documentation/en-US/Red_Hat_Update_Infrastructure/2.1/html/Administration_Guide/chap-Red_Hat_Update_Infrastructure-Administration_Guide-Certification_Revocation_List_CRL.html.

    As the database administrator (shown here as "postgres"), copy the CRL file into the data directory:

    As the system administrator, copy the CRL file into the PostgreSQL Data Directory:

    $ sudo cp root.crl ${PGDATA?}/root.crl

    As the database administrator (shown here as "postgres"), set the ssl_crl_file parameter to the filename of the CRL:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    ssl_crl_file = 'root.crl'

    In pg_hba.conf, require ssl authentication:

    $ sudo su - postgres
    $ vi ${PGDATA?}/pg_hba.conf
    hostssl <database> <user> <address> cert clientcert=verify-ca

    As the system administrator, reload the server with the new configuration:

    # SYSTEMD SERVER ONLY
    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag gid: 'V-261893'
  tag rid: 'SV-261893r1000684_rule'
  tag stig_id: 'CD16-00-004000'
  tag cci: ["CCI-000185"]
  tag nist: ["IA-5 (2) (b) (1)"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
