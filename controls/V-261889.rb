control 'V-261889' do
  title 'PostgreSQL must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'check', <<~EOT
    As the database administrator, run the following SQL:

    $ psql -c "SHOW port"
    $ psql -c "SHOW listen_addresses"

    If the currently defined address:port configuration is deemed prohibited, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

    To change the listening port of the database, as the database administrator, change the following setting in postgresql.conf: 

    $ sudo su - postgres 
    $ vi $PGDATA/postgresql.conf 

    Change the port parameter to the desired port. 

    To change the listening address of the database, as the database administrator, change the following setting in postgresql.conf: 
    listen_addresses = '10.0.0.1, 127.0.0.1'

    Restart the database: 

    # SYSTEMD SERVER ONLY 
    $ sudo systemctl restart postgresql-${PGVER?} 


    Note: psql uses the port 5432 by default. This can be changed by specifying the port with psql or by setting the PGPORT environment variable: 

    $ psql -p 5432 -c "SHOW port" 
    $ export PGPORT=5432
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag gid: 'V-261889'
  tag rid: 'SV-261889r1043177_rule'
  tag stig_id: 'CD16-00-003500'
  tag cci: ["CCI-000382"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session against the database.'
  end
end
