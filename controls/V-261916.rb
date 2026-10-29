control 'V-261916' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc <<~EOT
    In certain situations, to provide required functionality, PostgreSQL needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

    Privilege elevation must be used only where necessary and protected from misuse.

    This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.
  EOT
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
  tag nist: ["AC-6 (8)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # SECURITY DEFINER functions run with their owner's privileges. System schemas and
  # functions belonging to an extension are left out: extensions are approved under
  # V-261886. Approval is by schema.function name, so it covers every overload.
  approved = input('pg_approved_security_definer_functions')
  secdef_sql = "SELECT n.nspname || '.' || p.proname || '|' || pg_get_userbyid(p.proowner) FROM pg_proc p " \
               "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema') " \
               "AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e') ORDER BY 1;"
  functions, unreadable = rds_query_each_database(conn, sql, secdef_sql, /\A[^|]+\|[^|]+\z/)
  found = functions.map { |database, row| "#{row.split('|')[0]} owned by #{row.split('|')[1]} (#{database})" }
  unapproved = functions.reject { |_, row| approved.include?(row.split('|')[0]) }
                        .map { |database, row| "#{row.split('|')[0]} (#{database})" }
  describe "SECURITY DEFINER functions outside system schemas and extensions: #{found.empty? ? 'none' : found.join(', ')}" do
    it 'should be readable in every database (the scan account needs CONNECT on each)' do
      expect(unreadable).to be_empty
    end
    it 'should all be documented and approved via the pg_approved_security_definer_functions input' do
      expect(unapproved).to be_empty
    end
  end

  manual_note = 'Manually verify that each approved SECURITY DEFINER function is implemented as documented and can be invoked only in the intended ways, contexts and by the intended roles (check its EXECUTE grants).'
  describe manual_note do
    skip manual_note
  end
end
