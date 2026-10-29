control 'V-261891' do
  title 'If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.'
  desc <<~EOT
    The DOD standard for authentication is DOD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires Authorizing Official (AO) approval.

    In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to PostgreSQL.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGVER environment variables. Refer to supplementary content APPENDIX-H for PGVER.

    To check if password encryption is enabled, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW password_encryption"

    If password_encryption is not "scram-sha-256", this is a finding.

    To identify if any passwords have been stored without being hashed and salted, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -x -c "SELECT username, passwd FROM pg_shadow WHERE passwd IS NULL OR passwd NOT LIKE 'SCRAM-SHA-256%';"

    If any password is in plaintext, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To enable password_encryption, as the database administrator, edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    password_encryption = 'scram-sha-256'

    Institute a policy of not using the "WITH UNENCRYPTED PASSWORD" option with the CREATE ROLE/USER and ALTER ROLE/USER commands. (This option overrides the setting of the password_encryption configuration parameter.)

    As the system administrator, restart the server with the new configuration:

    # SYSTEMD SERVER ONLY
    $ sudo systemctl restart postgresql-${PGVER?}
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-261891'
  tag rid: 'SV-261891r1000970_rule'
  tag stig_id: 'CD16-00-003800'
  tag cci: ["CCI-000196"]
  # CCI-000196 has no NIST SP 800-53 Rev 5 mapping in the DISA CCI list (2025-01-23); Rev 4 reference used.
  tag nist: ["IA-5 (1) (c)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # Roles whose stored password isn't a SCRAM-SHA-256 hash, e.g. md5 hashes from before
  # password_encryption was changed. Roles with no password (IAM-only roles) are left out:
  # they have nothing stored. On RDS no customer role can read pg_shadow, not even the
  # master user (permission denied, checked on RDS PostgreSQL 17.11), so there this part is
  # a manual review. Elsewhere it runs, and any other query error fails the control.
  checks = [rds_setting_check(conn, sql, 'password_encryption', input('pg_password_encryption')), rds_apply_status_check(conn)]
  manual_note = nil
  stored_passwords = sql.query("SELECT usename FROM pg_shadow WHERE passwd IS NOT NULL AND passwd NOT LIKE 'SCRAM-SHA-256%';", [conn.db])
  if stored_passwords.output =~ /permission denied/i
    manual_note = "#{conn.dba} cannot read pg_shadow, so stored password hashes were not checked. On RDS no customer role can read it, not even the master user, so the hashes cannot be checked directly. Manually confirm every password-authenticated role had its password set or reset while password_encryption was scram-sha-256. With rds.accepted_password_auth_method set to scram (V-261892), a role whose stored hash is older cannot log in."
  else
    checks << rds_check('Roles with a stored password that is not a SCRAM-SHA-256 hash') do
      output = stored_passwords.output.strip
      [output.empty?, output.empty? ? 'none' : output.lines.map(&:strip).join(', ')]
    end
  end
  rds_review_results(checks, manual_note).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
