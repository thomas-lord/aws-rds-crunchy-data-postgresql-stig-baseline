control 'V-261926' do
  title 'PostgreSQL must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'check', <<~EOT
    As the database administrator, run the following SQL:

    $ psql -c "SHOW port"

    If the currently defined port configuration is deemed prohibited, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To change the listening port of the database, as the database administrator, change the following setting in postgresql.conf: 

    $ sudo su - postgres 
    $ vi $PGDATA/postgresql.conf 

    Change the port parameter to the desired port. 

    Restart the database: 

    $ sudo systemctl restart postgresql-${PGVER?} 

    Note: psql uses the port 5432 by default. This can be changed by specifying the port with psql or by setting the PGPORT environment variable: 

    $ psql -p 5432 -c "SHOW port" 
    $ export PGPORT=5432
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag gid: 'V-261926'
  tag rid: 'SV-261926r1000783_rule'
  tag stig_id: 'CD16-00-008000'
  tag cci: ["CCI-001762"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
