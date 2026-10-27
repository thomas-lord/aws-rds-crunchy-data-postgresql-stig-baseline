control 'V-261923' do
  title 'PostgreSQL must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
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
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
