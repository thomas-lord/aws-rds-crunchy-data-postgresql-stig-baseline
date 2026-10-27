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
  aws_ready = command('aws').exist?
  only_if('The AWS CLI must be installed and configured with credentials, and the aws_db_instance_identifier input must be set, to evaluate this control.') do
    aws_ready && !input('aws_db_instance_identifier').empty?
  end

  region_flag = input('aws_region').empty? ? '' : "--region #{input('aws_region')}"
  profile_flag = input('aws_cli_profile').empty? ? '' : "--profile #{input('aws_cli_profile')}"

  require 'json'

  sg_ids_cmd = "aws rds describe-db-instances --db-instance-identifier #{input('aws_db_instance_identifier')} #{region_flag} #{profile_flag} --query 'DBInstances[0].VpcSecurityGroups[].VpcSecurityGroupId' --output text"
  sg_ids_result = command(sg_ids_cmd)
  sg_ids = sg_ids_result.exit_status.zero? ? sg_ids_result.stdout.split : []

  # An RDS instance in a VPC always has at least one security group; an empty list
  # means the lookup failed, which must fail the control rather than yield no tests.
  describe 'RDS instance VPC security group lookup' do
    it "should return at least one security group (aws exit #{sg_ids_result.exit_status}: #{sg_ids_result.stderr.strip})" do
      expect(sg_ids).not_to be_empty
    end
  end

  approved_cidrs = input('pg_approved_ingress_cidrs')

  sg_ids.each do |sg_id|
    perms_cmd = "aws ec2 describe-security-groups --group-ids #{sg_id} #{region_flag} #{profile_flag} --query 'SecurityGroups[0].IpPermissions' --output json"
    result = command(perms_cmd)
    ingress_cidrs = []
    lookup_error = nil
    if result.exit_status.zero?
      begin
        JSON.parse(result.stdout).each do |perm|
          (perm['IpRanges'] || []).each { |r| ingress_cidrs << r['CidrIp'] }
        end
      rescue JSON::ParserError => e
        lookup_error = "unparseable output: #{e.message}"
      end
    else
      lookup_error = "aws exit #{result.exit_status}: #{result.stderr.strip}"
    end

    describe "Security group #{sg_id} ingress CIDRs (#{ingress_cidrs.join(', ')})" do
      # Without this, a failed lookup leaves ingress_cidrs empty and both checks below pass.
      it "should be readable via ec2:DescribeSecurityGroups#{lookup_error ? " (#{lookup_error})" : ''}" do
        expect(lookup_error).to be_nil
      end
      it "should not include the public 0.0.0.0/0 range" do
        expect(ingress_cidrs).not_to include('0.0.0.0/0')
      end
      it 'should only include CIDRs approved via the pg_approved_ingress_cidrs input (PPSM CAL / vulnerability assessment)' do
        expect(ingress_cidrs - approved_cidrs).to be_empty
      end
    end
  end
end
