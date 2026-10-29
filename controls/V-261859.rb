control 'V-261859' do
  title 'PostgreSQL must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc <<~EOT
    Authentication with a DOD-approved PKI certificate does not necessarily imply authorization to access PostgreSQL. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems, including databases, must be properly configured to implement access control policies.

    Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

    Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

    This requirement is applicable to access control enforcement applications, a category that includes database management systems. If PostgreSQL does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.
  EOT
  desc 'check', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    From the system security plan or equivalent documentation, determine the appropriate permissions on database objects for each kind (group role) of user. If this documentation is missing, this is a finding.

    As the database administrator (shown here as "postgres"), check the privileges of all roles in the database by running the following SQL:

    $ sudo su - postgres
    $ psql -c '\du'

    Review all roles and their associated privileges. If any roles' privileges exceed those documented, this is a finding.

    As the database administrator (shown here as "postgres"), check the configured privileges for tables and columns by running the following SQL:

    $ sudo su - postgres
    $ psql -c '\dp'

    Review all access privileges and column access privileges list. If any roles' privileges exceed those documented, this is a finding.

    As the database administrator (shown here as "postgres"), check the configured authentication settings in pg_hba.conf:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_hba.conf

    Review all entries and their associated authentication methods. If any entries do not have their documented authentication requirements, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

    Create and/or maintain documentation of each group role's appropriate permissions on database objects.

    Implement these permissions in the database and remove any permissions that exceed those documented.

    The following are examples of how to use role privileges in PostgreSQL to enforce access controls. For a complete list of privileges, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html. 

    #### Roles Example 1 

    The following example demonstrates how to create an admin role with CREATEDB and CREATEROLE privileges. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "CREATE ROLE admin WITH CREATEDB CREATEROLE" 

    #### Roles Example 2 

    The following example demonstrates how to create a role with a password that expires and makes the role a member of the "admin" group. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "CREATE ROLE joe LOGIN ENCRYPTED PASSWORD 'stig_2024' VALID UNTIL '2024-09-20' IN ROLE admin" 

    #### Roles Example 3 

    The following demonstrates how to revoke privileges from a role using REVOKE. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "REVOKE admin FROM joe" 

    #### Roles Example 4 

    The following demonstrates how to alter privileges in a role using ALTER. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "ALTER ROLE joe NOLOGIN" 

    The following are examples of how to use grant privileges in PostgreSQL to enforce access controls on objects. For a complete list of privileges, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-grant.html. 

    #### Grant Example 1 

    The following example demonstrates how to grant INSERT on a table to a role. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "GRANT SELECT ON stig_test TO joe" 

    #### Grant Example 2 

    The following example demonstrates how to grant ALL PRIVILEGES on a table to a role. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "GRANT ALL PRIVILEGES ON stig_test TO joe" 

    #### Grant Example 3 

    The following example demonstrates how to grant a role to a role. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "GRANT admin TO joe" 

    #### Revoke Example 1 

    The following example demonstrates how to revoke access from a role. 

    As the database administrator (shown here as "postgres"), run the following SQL: 

    $ sudo su - postgres 

    $ psql -c "REVOKE admin FROM joe" 

    To change authentication requirements for the database, as the database administrator (shown here as "postgres"), edit pg_hba.conf: 

    $ sudo su - postgres 

    $ vi ${PGDATA?}/pg_hba.conf 

    Edit authentication requirements to the organizational requirements. Refer to the official documentation for the complete list of options for authentication: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html. 

    After changes to pg_hba.conf, reload the server: 

    $ sudo systemctl reload postgresql-${PGVER?}
  EOT
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag gid: 'V-261859'
  tag rid: 'SV-261859r1137654_rule'
  tag stig_id: 'CD16-00-000300'
  tag cci: ["CCI-000213"]
  tag nist: ["AC-3"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  # The documented authorizations are the approval inputs: pg_approved_admin_roles for role
  # attributes (\du) and pg_approved_object_privileges for grants on tables, views, sequences
  # and their columns (\dp), checked in every database. pg_hba.conf can't be read on RDS; its
  # authentication methods are covered by V-261858 (password vs IAM/Kerberos) and V-261892 (SCRAM).
  attribute_sql = "SELECT rolname || '|' || concat_ws(',', CASE WHEN rolsuper THEN 'SUPERUSER' END, CASE WHEN rolcreaterole THEN 'CREATEROLE' END, " \
                  "CASE WHEN rolcreatedb THEN 'CREATEDB' END, CASE WHEN rolbypassrls THEN 'BYPASSRLS' END, CASE WHEN rolreplication THEN 'REPLICATION' END) " \
                  "FROM pg_roles WHERE (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication) AND rolname !~ '^pg_' AND rolname <> 'rdsadmin' ORDER BY 1;"
  grantee_sql = "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END"
  user_schema_sql = "n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"
  grant_sql = "SELECT grantee || '|' || privilege || '|' || count(DISTINCT object) FROM (" \
              "SELECT #{grantee_sql} AS grantee, a.privilege_type AS privilege, c.oid AS object " \
              "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a " \
              "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND a.grantee <> c.relowner AND #{user_schema_sql} " \
              "AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') " \
              "UNION ALL SELECT #{grantee_sql}, a.privilege_type || ' (columns)', c.oid " \
              "FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(t.attacl) a " \
              "WHERE a.grantee <> c.relowner AND #{user_schema_sql}) g GROUP BY grantee, privilege ORDER BY 1;"

  approved_admins = input('pg_approved_admin_roles')
  approved_privileges = input('pg_approved_object_privileges').to_h { |role, privileges| [role.to_s, Array(privileges).map(&:upcase)] }
  checks = [
    rds_check('Roles with SUPERUSER, CREATEROLE, CREATEDB, BYPASSRLS or REPLICATION, approved via pg_approved_admin_roles') do
      rows = sql.query(attribute_sql, [conn.db]).lines
      raise rows.join(' ') unless rows.all? { |row| row =~ /\A[^|]+\|[A-Z,]+\z/ }

      found = rows.map { |row| "#{row.split('|')[0]} (#{row.split('|')[1]})" }
      unapproved = rows.map { |row| row.split('|')[0] } - approved_admins
      [unapproved.empty?, rds_approval_summary(found, unapproved)]
    end
  ]
  grants, unreadable = rds_query_each_database(conn, sql, grant_sql, /\A[^|]+\|[^|]+\|\d+\z/)
  checks << rds_check('Databases readable (the scan account needs CONNECT on each)') { [unreadable.empty?, unreadable.empty? ? 'all' : "unreadable: #{unreadable.join(', ')}"] }
  checks << rds_check('Privileges on tables, views, sequences and columns granted to non-owners, approved via pg_approved_object_privileges') do
    found = []
    unapproved = []
    grants.each do |database, row|
      grantee, privilege, count = row.split('|')
      entry = "#{grantee} #{privilege} on #{count} in #{database}"
      found << entry
      unapproved << entry unless approved_privileges.fetch(grantee, []).include?(privilege.delete_suffix(' (columns)'))
    end
    [unapproved.empty?, rds_approval_summary(found, unapproved)]
  end
  rds_review_results(checks, nil).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
