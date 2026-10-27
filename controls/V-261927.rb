control 'V-261927' do
  title 'PostgreSQL must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'check', <<~EOT
    Determine all situations where a user must reauthenticate. Check if the mechanisms that handle such situations use the following SQL:

    To make a single user reauthenticate, the following must be present:

    SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'

    To make all users reauthenticate, run the following:

    SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'

    If the provided SQL does not force reauthentication, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Modify and/or configure PostgreSQL and related applications and tools so that users are always required to reauthenticate when changing role or escalating privileges.

    To make a single user reauthenticate, the following must be present:

    SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'

    To make all users reauthenticate, the following must be present:

    SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000389-DB-000372'
  tag gid: 'V-261927'
  tag rid: 'SV-261927r1050788_rule'
  tag stig_id: 'CD16-00-008100'
  tag cci: ["CCI-002038"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
