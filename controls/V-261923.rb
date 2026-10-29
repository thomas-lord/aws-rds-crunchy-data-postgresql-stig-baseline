control 'V-261923' do
  title 'PostgreSQL must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc <<~EOT
    Allowing regular users to install software without explicit privileges creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

    PostgreSQL functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

    PostgreSQL must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

    In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.
  EOT
  desc 'check', <<~EOT
    If PostgreSQL supports only software development, experimentation and/or developer-level testing (that is, excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding.

    Review PostgreSQL and database security settings with respect to nonadministrative users ability to create, alter, or replace logic modules, to include but not necessarily only stored procedures, functions, triggers, and views.

    To list the privileges for all tables and schemas, as the database administrator (shown here as "postgres"), run the following:

    $ sudo su - postgres
    $ psql -c "\dp"
    $ psql -c "\dn+"

    The privileges are as follows:

    rolename=xxxx -- privileges granted to a role
    =xxxx -- privileges granted to PUBLIC

    r -- SELECT ("read")
    w -- UPDATE ("write")
    a -- INSERT ("append")
    d -- DELETE
    D -- TRUNCATE
    x -- REFERENCES
    t -- TRIGGER
    X -- EXECUTE
    U -- USAGE
    C -- CREATE
    c -- CONNECT
    T -- TEMPORARY
    arwdDxt -- ALL PRIVILEGES (for tables, varies for other objects)
    * -- grant option for preceding privilege

    /yyyy -- role that granted this privilege

    If any such permissions exist and are not documented and approved, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Document and obtain approval for any nonadministrative users who require the ability to create, alter, or replace logic modules.

    Implement the approved permissions. Revoke any unapproved permissions.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag gid: 'V-261923'
  tag rid: 'SV-261923r1000993_rule'
  tag stig_id: 'CD16-00-007700'
  tag cci: ["CCI-001812"]
  # CCI-001812 has no NIST SP 800-53 Rev 5 mapping in the DISA CCI list (2025-01-23); Rev 4 reference used.
  tag nist: ["CM-11 (2)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # Who besides an owner can create logic modules: CREATE on a schema lets a role add
  # functions, views and triggers there, and CREATE on a database lets it make schemas of
  # its own. Grants to PUBLIC or to roles not in pg_approved_schema_creators are flagged.
  # Owners always can, and are the manual part below; rds_superuser holders, who can do
  # anything, are checked by V-261924.
  approved = input('pg_approved_schema_creators')
  grantee_sql = "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END"
  schema_sql = "SELECT n.nspname || '|' || #{grantee_sql} FROM pg_namespace n, aclexplode(n.nspacl) a " \
               "WHERE a.privilege_type = 'CREATE' AND a.grantee <> n.nspowner AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY 1;"
  schema_grants, unreadable = rds_query_each_database(conn, sql, schema_sql, /\A[^|]+\|[^|]+\z/)
  database_sql = "SELECT d.datname || '|' || #{grantee_sql} FROM pg_database d, aclexplode(d.datacl) a " \
                 "WHERE a.privilege_type = 'CREATE' AND a.grantee <> d.datdba AND d.datname <> 'rdsadmin' ORDER BY 1;"
  database_rows = sql.query(database_sql, [conn.db]).lines
  unreadable += ['(database privileges)'] unless database_rows.all? { |row| row =~ /\A[^|]+\|[^|]+\z/ }

  grants = schema_grants.map { |database, row| ["schema #{database}.#{row.split('|')[0]}", row.split('|')[1]] } +
           database_rows.grep(/\A[^|]+\|[^|]+\z/).map { |row| ["database #{row.split('|')[0]}", row.split('|')[1]] }
  found = grants.map { |object, grantee| "#{grantee} on #{object}" }
  unapproved = grants.reject { |_, grantee| approved.include?(grantee) }.map { |object, grantee| "#{grantee} on #{object}" }
  checks = [
    rds_check('Databases readable (the scan account needs CONNECT on each)') { [unreadable.empty?, unreadable.empty? ? 'all' : "unreadable: #{unreadable.join(', ')}"] },
    rds_check('CREATE on schemas and databases granted to non-owners, never PUBLIC and only roles in pg_approved_schema_creators') { [unapproved.empty?, rds_approval_summary(found, unapproved)] }
  ]
  manual_note = 'Manually verify that the roles owning databases and schemas, which can always create objects in them, are administrative roles documented as approved. (Not a finding if this instance only supports development or experimentation.)'
  rds_review_results(checks, manual_note).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
