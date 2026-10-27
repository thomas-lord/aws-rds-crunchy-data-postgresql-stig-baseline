control 'V-261957' do
  title 'PostgreSQL must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA and PGLOG environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I on PGLOG.

    In this example the user "joe" will log in to the Postgres database unsuccessfully:

    $ psql -d postgres -U joe

    As the database administrator (shown here as "postgres"), check ${PGLOG?} for a FATAL connection audit trail:

    $ sudo su - postgres
    $ cat ${PGDATA?}/${PGLOG?}/{latest_log>
    < 2024-02-16 16:18:13.027 UTC joe 56c65135.b5f postgres: >LOG: connection authorized: user=joe database=postgres
    < 2024-02-16 16:18:13.027 UTC joe 56c65135.b5f postgres: >FATAL: role "joe" does not exist

    If an audit record is not generated each time a user (or other principal) attempts, but fails to log on or connect to PostgreSQL (including attempts where the user ID is invalid/unknown), this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    If logging is enabled the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier.

    As the database administrator (shown here as "postgres"), edit postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf

    Edit the following parameters:

    log_connections = on
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
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag gid: 'V-261957'
  tag rid: 'SV-261957r1000876_rule'
  tag stig_id: 'CD16-00-011300'
  tag cci: ["CCI-000172"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
