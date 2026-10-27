control 'V-261924' do
  title 'PostgreSQL must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'check', <<~EOT
    To list all the permissions of individual roles, as the database administrator (shown here as "postgres"), run the following SQL:

    $ sudo su - postgres
    $ psql -c "\du"

    If any role has SUPERUSER that should not, this is a finding.

    List all the permissions of databases and schemas by running the following SQL:

    $ sudo su - postgres
    $ psql -c "\l"
    $ psql -c "\dn+"

    If any database or schema has update ("W") or create ("C") privileges and should not, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

    Use ALTER ROLE to remove accesses from roles:

    $ psql -c "ALTER ROLE <role_name> NOSUPERUSER"

    Use REVOKE to remove privileges from databases and schemas:

    $ psql -c "REVOKE ALL PRIVILEGES ON <table> FROM <role_name>"
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag gid: 'V-261924'
  tag rid: 'SV-261924r1000777_rule'
  tag stig_id: 'CD16-00-007800'
  tag cci: ["CCI-001813"]
  tag nist: []
  conn = aws_rds_connection(
    aws_instance_id: input('aws_db_instance_identifier'),
    region: input('aws_region'),
    profile: input('aws_cli_profile'),
    host: input('pg_host'),
    port: input('pg_port'),
    db: input('pg_db'),
    dba: input('pg_dba')
  )
  sql = postgres_session(conn.dba, input('pg_dba_password'), conn.host, conn.port)

  unauthorized_superusers_sql = "SELECT rolname FROM pg_roles WHERE rolsuper = true;"
  describe sql.query(unauthorized_superusers_sql, [conn.db]).lines do
    it { should all(be_in input('pg_superusers')) }
  end

  describe 'Manually review database/schema-level privileges (\\l and \\dn+ output) for unauthorized update ("W") or create ("C") grants; this portion cannot be fully automated without an organization-defined authorization matrix.' do
    skip 'Manually review database/schema-level privileges (\\l and \\dn+ output) for unauthorized update ("W") or create ("C") grants; this portion cannot be fully automated without an organization-defined authorization matrix.'
  end
end
