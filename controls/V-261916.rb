control 'V-261916' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'check', <<~EOT
    Functions in PostgreSQL can be created with the SECURITY DEFINER option. When SECURITY DEFINER functions are executed by a user, said function is run with the privileges of the user who created it.

    To list all functions that have SECURITY DEFINER, as, the DBA (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL"

    In the query results, a prosecdef value of "t" on a row indicates that that function uses privilege elevation.

    If elevation of PostgreSQL privileges is used but not documented, this is a finding.

    If elevation of PostgreSQL privileges is documented, but not implemented as described in the documentation, this is a finding.

    If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Determine where, when, how, and by what principals/subjects elevated privilege is needed.

    To change a SECURITY DEFINER function to SECURITY INVOKER, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "ALTER FUNCTION <function_name> SECURITY INVOKER"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag gid: 'V-261916'
  tag rid: 'SV-261916r1000981_rule'
  tag stig_id: 'CD16-00-006900'
  tag cci: ["CCI-002233"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
