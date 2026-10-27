# Custom InSpec resource: resolves PostgreSQL connection parameters for an AWS RDS
# instance via the AWS CLI (`aws rds describe-db-instances`) when an instance
# identifier is configured, falling back to the manually supplied inputs otherwise.
#
# This does not replace the pg_host/pg_port/pg_db/pg_dba inputs; it layers AWS
# discovery on top of them so that only `pg_dba_password` (a secret the AWS API
# cannot provide) must always be supplied manually.
module Inspec::Resources
  class AwsRdsConnection < Inspec.resource(1)
    name 'aws_rds_connection'
    desc 'Resolves RDS PostgreSQL connection details (host/port/db/master user), preferring AWS CLI discovery over manual inputs.'
    example <<~EXAMPLE
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
    EXAMPLE

    def initialize(opts = {})
      @aws_instance_id = opts[:aws_instance_id].to_s
      @region = opts[:region].to_s
      @profile = opts[:profile].to_s
      @manual_host = opts[:host].to_s
      @manual_port = opts[:port]
      @manual_db = opts[:db].to_s
      @manual_dba = opts[:dba].to_s
      @cache = {}
    end

    def host
      aws_attr('Endpoint.Address') || @manual_host
    end

    def port
      (aws_attr('Endpoint.Port') || @manual_port).to_i
    end

    def db
      aws_attr('DBName') || @manual_db
    end

    def dba
      aws_attr('MasterUsername') || @manual_dba
    end

    # Whether AWS CLI discovery was actually usable (CLI present, instance ID set).
    def aws_available?
      return @aws_available if defined?(@aws_available)
      @aws_available = !@aws_instance_id.empty? && inspec.command('aws').exist?
    end

    # The RDS DB instance's parameter-group apply status (e.g. "in-sync" or
    # "pending-reboot"). Returns nil when AWS discovery is unavailable.
    def parameter_apply_status
      aws_attr('DBParameterGroups[0].ParameterApplyStatus')
    end

    def to_s
      "aws_rds_connection(#{@aws_instance_id.empty? ? 'manual' : @aws_instance_id})"
    end

    private

    def aws_attr(query_path)
      return nil unless aws_available?
      return @cache[query_path] if @cache.key?(query_path)

      region_flag = @region.empty? ? '' : "--region #{@region}"
      profile_flag = @profile.empty? ? '' : "--profile #{@profile}"
      cmd = "aws rds describe-db-instances --db-instance-identifier #{@aws_instance_id} " \
            "#{region_flag} #{profile_flag} --query 'DBInstances[0].#{query_path}' --output text"
      result = inspec.command(cmd)
      value = result.exit_status.zero? ? result.stdout.strip : nil
      value = nil if value.nil? || value.empty? || value == 'None'
      @cache[query_path] = value
      value
    end
  end
end
