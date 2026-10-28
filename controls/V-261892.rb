control 'V-261892' do
  title 'If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of passwords.'
  desc <<~EOT
    The DOD standard for authentication is DOD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires Authorizing Official (AO) approval.

    In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

    PostgreSQL passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    As the database administrator (shown here as "postgres"), review the authentication entries in pg_hba.conf:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_hba.conf

    If any entries use the auth_method (last column in records) "password" or "md5", this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file and change all entries of "password" to "scram-sha-256":

    $ sudo su - postgres
    $ vi ${PGDATA?}/pg_hba.conf
    host all all .example.com scram-sha-256
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag gid: 'V-261892'
  tag rid: 'SV-261892r1000681_rule'
  tag stig_id: 'CD16-00-003900'
  tag cci: ["CCI-000197"]
  tag nist: ["IA-5 (1) (c)"]
  # RDS doesn't expose pg_hba.conf. Its equivalent of "no password or md5 entries" is the
  # rds.accepted_password_auth_method parameter: 'scram' rejects every password method except
  # SCRAM-SHA-256 (the default, 'md5+scram', still accepts md5). password_encryption must also
  # be scram-sha-256, or new passwords get md5 hashes and those roles can no longer log in.
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW rds.accepted_password_auth_method;', [conn.db]) do
    its('output.strip') { should cmp 'scram' }
  end

  describe sql.query('SHOW password_encryption;', [conn.db]) do
    its('output.strip') { should cmp input('pg_password_encryption') }
  end

  # rds.force_ssl encrypts the whole connection, so even the SCRAM exchange never crosses the
  # network in the clear.
  describe sql.query('SHOW rds.force_ssl;', [conn.db]) do
    its('output.strip') { should cmp '1' }
  end

  rds_check_parameter_apply_status(conn)
end
