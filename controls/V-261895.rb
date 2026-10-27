control 'V-261895' do
  title 'PostgreSQL must map the PKI-authenticated identity to an associated user account.'
  desc 'check', <<~EOT
    The Common Name (cn) attribute of the certificate will be compared to the requested database username and, if they match, the login will be allowed.

    To check the cn of the certificate, using openssl, do the following:

    $ openssl x509 -noout -subject -in /path/to/your/client_cert.file

    If the cn does not match the users listed in PostgreSQL and no user mapping is used, this is a finding.

    User name mapping can be used to allow cn to be different from the database username. If User Name Maps are used, run the following as the database administrator (shown here as "postgres"), to get a list of maps used for authentication:

    $ sudo su - postgres
    $ grep "map" ${PGDATA?}/pg_hba.conf

    With the names of the maps used, check those maps against the username mappings in pg_ident.conf:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_ident.conf

    If user accounts are not being mapped to authenticated identities, this is a finding.

    If the cn and the username mapping do not match, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Configure PostgreSQL to map authenticated identities directly to PostgreSQL user accounts.

    For information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag gid: 'V-261895'
  tag rid: 'SV-261895r1000690_rule'
  tag stig_id: 'CD16-00-004200'
  tag cci: ["CCI-000187"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
