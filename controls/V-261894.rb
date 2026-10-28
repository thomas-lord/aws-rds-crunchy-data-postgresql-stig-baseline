control 'V-261894' do
  title 'PostgreSQL must enforce authorized access to all PKI private keys stored/used by PostgreSQL.'
  desc <<~EOT
    The DOD standard for authentication is DOD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where the DBMS-stored private keys are used to authenticate PostgreSQL to the system's clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the PostgreSQL system and its clients.

    Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 or 140-3 validated cryptographic modules.

    All access to the private key(s) of PostgreSQL must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of PostgreSQL's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions.
  EOT
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), verify the following settings:

    $ sudo su - postgres
    $ psql -c "select name,                                                         case when setting = '' then                                                                            '<undefined>'                                                                                      when substring(setting, 1, 1) = '/' then                                                               setting                                                                                            else (select setting from pg_settings where name = 'data_directory') || '/' || setting               end as setting                                                                                     from pg_settings                                                                                     where name in ('ssl_ca_file', 'ssl_cert_file', 'ssl_crl_file', 'ssl_key_file');"

    If the directory in which these files are stored is not protected, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Store all PostgreSQL PKI private keys in a FIPS 140-2-validated cryptographic module.

    Ensure access to PostgreSQL PKI private keys is restricted to only authenticated and authorized users.

    PostgreSQL private key(s) can be stored in $PGDATA directory, which is only accessible by the database owner (usually postgres, DBA) user. Do not allow access to this system account to unauthorized users.

    To put the keys in a different directory, as the database administrator (shown here as "postgres"), set the following settings to a protected directory:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    ssl_ca_file = "/some/protected/directory/root.crt"
    ssl_crl_file = "/some/protected/directory/root.crl"
    ssl_cert_file = "/some/protected/directory/server.crt"
    ssl_key_file = "/some/protected/directory/server.key"

    As the system administrator, restart the server with the new configuration:

    # SYSTEMD SERVER ONLY
    $ sudo systemctl restart postgresql-${PGVER?}

    For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag gid: 'V-261894'
  tag rid: 'SV-261894r1000687_rule'
  tag stig_id: 'CD16-00-004100'
  tag cci: ["CCI-000186"]
  tag nist: ["IA-5 (2) (a) (1)"]
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
