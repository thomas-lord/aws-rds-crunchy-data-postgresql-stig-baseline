require 'json'

# Custom InSpec resource: resolves PostgreSQL connection parameters for an AWS RDS
# instance via the AWS CLI (`aws rds describe-db-instances`) when an instance
# identifier is configured, falling back to the manually supplied inputs otherwise.
#
# This does not replace the pg_host/pg_port/pg_db/pg_dba inputs; it layers AWS
# discovery on top of them so that only `pg_dba_password` (a secret the AWS API
# cannot provide) must always be supplied manually.
#
# It also acts as the profile's preflight gate: `sql_session` verifies the SQL
# session actually works before any control queries it, and an AWS lookup that
# was requested but failed raises instead of silently falling back. Either
# failure makes every dependent control fail with the underlying error, rather
# than letting a dead connection produce empty output that some checks would
# read as passing.
module Inspec::Resources
  class AwsRdsConnectionError < StandardError; end

  class AwsRdsConnection < Inspec.resource(1)
    name 'aws_rds_connection'
    desc 'Resolves RDS PostgreSQL connection details (host/port/db/master user), preferring AWS CLI discovery over manual inputs, and verifies the SQL session before use.'
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
      sql = conn.sql_session(input('pg_dba_password'))
    EXAMPLE

    # Shared across controls (each control builds its own resource instance) so the
    # AWS describe call and the SQL connectivity probe each run once per scan, and a
    # bad password is only tried once rather than once per control. Failures are
    # cached too, so every control reports the same original error.
    @instance_cache = {}
    @session_cache = {}
    class << self
      attr_reader :instance_cache, :session_cache
    end

    def initialize(opts = {})
      @aws_instance_id = opts[:aws_instance_id].to_s
      @region = opts[:region].to_s
      @profile = opts[:profile].to_s
      @manual_host = opts[:host].to_s
      @manual_port = opts[:port]
      @manual_db = opts[:db].to_s
      @manual_dba = opts[:dba].to_s
    end

    def host
      aws_attr('Endpoint', 'Address') || @manual_host
    end

    def port
      (aws_attr('Endpoint', 'Port') || @manual_port).to_i
    end

    def db
      aws_attr('DBName') || @manual_db
    end

    def dba
      aws_attr('MasterUsername') || @manual_dba
    end

    # Whether AWS CLI discovery is in use (CLI present, instance ID set). When true,
    # a failed lookup raises rather than falling back to the manual inputs.
    def aws_available?
      return @aws_available if defined?(@aws_available)
      @aws_available = !@aws_instance_id.empty? && inspec.command('aws').exist?
    end

    # Any field of the cached `describe-db-instances` result, e.g.
    # aws_instance_attr('StorageEncrypted'). Returns nil when AWS discovery is
    # unavailable; raises (like host/port) if discovery was requested but failed.
    def aws_instance_attr(*path)
      aws_attr(*path)
    end

    # The RDS DB instance's parameter-group apply status (e.g. "in-sync" or
    # "pending-reboot"). Returns nil when AWS discovery is unavailable.
    def parameter_apply_status
      groups = aws_attr('DBParameterGroups')
      groups.is_a?(Array) && !groups.empty? ? groups[0]['ParameterApplyStatus'] : nil
    end

    # A postgres_session that has been proven to work. Raises (failing the calling
    # control) if `SELECT 1` doesn't come back as exactly "1" -- which covers an
    # unreachable host, bad credentials, a missing psql client, etc.
    def sql_session(password)
      session = inspec.postgres_session(dba, password, host, port)
      key = [dba, host, port, db]
      cache = self.class.session_cache
      unless cache.key?(key)
        output = begin
          session.query('SELECT 1;', [db]).output.to_s.strip
        rescue StandardError => e
          e.message
        end
        cache[key] = output == '1' ? nil : output
      end
      if cache[key]
        raise AwsRdsConnectionError,
              "Preflight failed: cannot run SQL against #{dba}@#{host}:#{port}/#{db} " \
              "(connection source: #{aws_available? ? "AWS CLI discovery for #{@aws_instance_id}" : 'manual inputs'}). " \
              "psql output: #{cache[key].empty? ? '(none)' : cache[key]}"
      end
      session
    end

    def to_s
      "aws_rds_connection(#{@aws_instance_id.empty? ? 'manual' : @aws_instance_id})"
    end

    private

    def aws_attr(*path)
      return nil unless aws_available?
      value = describe_instance.dig(*path)
      value.nil? || value == '' ? nil : value
    end

    def describe_instance
      key = [@aws_instance_id, @region, @profile]
      cache = self.class.instance_cache
      cache[key] ||= fetch_instance
      raise AwsRdsConnectionError, cache[key][:error] if cache[key][:error]
      cache[key][:data]
    end

    def fetch_instance
      region_flag = @region.empty? ? '' : "--region #{@region}"
      profile_flag = @profile.empty? ? '' : "--profile #{@profile}"
      cmd = "aws rds describe-db-instances --db-instance-identifier #{@aws_instance_id} " \
            "#{region_flag} #{profile_flag} --query 'DBInstances[0]' --output json"
      result = inspec.command(cmd)
      unless result.exit_status.zero?
        return { error: "Preflight failed: `aws rds describe-db-instances` for #{@aws_instance_id} " \
                        "exited #{result.exit_status}: #{result.stderr.strip}" }
      end
      data = JSON.parse(result.stdout)
      return { error: "Preflight failed: no RDS instance data returned for #{@aws_instance_id}" } unless data.is_a?(Hash)
      { data: data }
    rescue JSON::ParserError => e
      { error: "Preflight failed: could not parse `aws rds describe-db-instances` output for #{@aws_instance_id}: #{e.message}" }
    end
  end
end
