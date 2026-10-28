control 'V-261900' do
  title 'PostgreSQL must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc <<~EOT
    One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

    The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 or 140-3 approved random number generator.

    However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.
  EOT
  desc 'check', <<~EOT
    To check if PostgreSQL is configured to use ssl, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW ssl"

    If this is not set to on, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To configure PostgreSQL to use SSL, as a database owner (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Add the following parameter:

    ssl = on

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}

    For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

    For further SSL configurations, refer to the official documentation: https://www.postgresql.org/docs/current/static/ssl-tcp.html.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag gid: 'V-261900'
  tag rid: 'SV-261900r1043181_rule'
  tag stig_id: 'CD16-00-004900'
  tag cci: ["CCI-001188"]
  tag nist: ["SC-23 (3)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW ssl;', [conn.db]) do
    its('output.strip') { should cmp input('pg_ssl') }
  end

  rds_check_parameter_apply_status(conn)
end
