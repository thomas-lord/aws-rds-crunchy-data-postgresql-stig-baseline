control 'V-261910' do
  title 'PostgreSQL must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc 'check', <<~EOT
    Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

    If the documentation requires automatic session termination, but PostgreSQL is not configured accordingly, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to automatically terminate a user session after organization-defined conditions or trigger events requiring session termination.

    Examples follow.

    ### Change a role to nologin and disconnect the user

    ALTER ROLE '<username>' NOLOGIN;
    SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='<usename>';

    ### Disconnecting users during a specific time range
    Refer to supplementary content APPENDIX-A for a bash script for this example.

    The script found in APPENDIX-A using the -l command can disable all users with rolcanlogin=t from logging in. The script keeps track of who it disables in a .restore_login file. After the specified time is over, the same script can be run with the -r command to restore all login connections.

    This script would be added to a cron job:

    # lock at 5 am every day of the week, month, year at the 0 minute mark.
    0 5 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -l
    # restore at 5 pm every day of the week, month, year at the 0 minute mark.
    0 17 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -r
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag gid: 'V-261910'
  tag rid: 'SV-261910r1043182_rule'
  tag stig_id: 'CD16-00-006200'
  tag cci: ["CCI-002361"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
