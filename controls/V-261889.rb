control 'V-261889' do
  title 'PostgreSQL must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc <<~EOT
    In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

    Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

    To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

    Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.
  EOT
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
  tag nist: ["CM-7 b"]
  conn = rds_connection
  rds_only_if_aws(conn)

  # An RDS instance in a VPC always has at least one security group; an empty list
  # means the lookup found nothing to check, which must not read as a pass.
  groups = conn.security_group_ingress
  describe 'RDS instance VPC security groups' do
    subject { groups }
    it { should_not be_empty }
  end

  rds_check_security_group_ingress(groups)
end
