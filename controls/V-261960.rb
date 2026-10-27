control 'V-261960' do
  title 'PostgreSQL must generate audit records showing starting and ending time for user access to the database(s).'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

    Log into the database with the postgres user by running the following commands:

    $ sudo su - postgres
    $ psql -U postgres

    As the database administrator, verify the log for a connection audit trail:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/<latest_log>
    < 2024-02-23 20:25:39.931 UTC postgres 56cfa993.7a72 postgres: >LOG: connection authorized: user=postgres database=postgres
    < 2024-02-23 20:27:45.428 UTC postgres 56cfa993.7a72 postgres: >LOG: AUDIT: SESSION,1,1,READ,SELECT,,,SELECT current_user;,<none>
    < 2024-02-23 20:27:47.988 UTC postgres 56cfa993.7a72 postgres: >LOG: disconnection: session time: 0:00:08.057 user=postgres database=postgres host=[local]

    If connections are not logged, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    If logging is enabled the following configurations must be made to log connections, date/time, username, and session identifier.

    As the database administrator (shown here as "postgres"), edit postgresql.conf by running the following:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Edit the following parameters:

    log_connections = on
    log_disconnections = on
    log_line_prefix = '< %m %u %c: >'

    Where:
    * %m is the time and date
    * %u is the username
    * %c is the session ID for the connection

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: 'V-261960'
  tag rid: 'SV-261960r1000885_rule'
  tag stig_id: 'CD16-00-011600'
  tag cci: ["CCI-000172"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
