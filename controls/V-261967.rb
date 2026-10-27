control 'V-261967' do
  title 'PostgreSQL must offload audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for standalone systems.'
  desc 'check', <<~EOT
    As the database administrator (shown here as "postgres"), ensure PostgreSQL uses syslog by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW log_destination"

    If log_destination is not syslog, this is a finding.

    As the database administrator, check which log facility is configured by running the following SQL:

    $ psql -c "SHOW syslog_facility" 

    Check with the organization to refer to how syslog facilities are defined in their organization.

    If the wrong facility is configured, this is a finding.

    If PostgreSQL does not have a continuous network connection to the centralized log management system, and PostgreSQL audit records are not transferred to the centralized log management system weekly or more often, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system, continuously and in near real time where a continuous network connection to the log management system exists, or at least weekly in the absence of such a connection.

    To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

    With logging enabled, as the database administrator (shown here as "postgres"), configure the following parameters in postgresql.conf (the example uses the default values - tailor for environment):

    Note: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    log_destination = 'syslog'
    syslog_facility = 'LOCAL0'
    syslog_ident = 'postgres'

    As the system administrator, reload the server with the new configuration:

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag gid: 'V-261967'
  tag rid: 'SV-261967r1000906_rule'
  tag stig_id: 'CD16-00-012400'
  tag cci: ["CCI-001851"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
