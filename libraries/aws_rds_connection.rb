require 'json'
require 'shellwords'

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
    #
    # Always reach these through AwsRdsConnection, never self.class: InSpec
    # instantiates resources via an anonymous subclass, which doesn't see the
    # parent's class-level instance variables.
    @instance_cache = {}
    @session_cache = {}
    @kms_cache = {}
    class << self
      attr_reader :instance_cache, :session_cache, :kms_cache
    end

    # InSpec's registry subclass calls super into this; it must not call super itself.
    def initialize(opts = {}) # rubocop:disable Lint/MissingSuper
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
      cache = AwsRdsConnection.session_cache
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

    # --- AWS-side lookups for the AWS CLI-based controls ---------------------------
    # Each raises AwsRdsConnectionError (failing the calling control with the AWS
    # error) when the CLI call fails, so a lookup failure can never read as "no
    # findings". Each returns [] when AWS discovery isn't in use: a control skipped
    # by only_if still evaluates its body, which must not shell out to a missing CLI.

    # Ingress that can reach the database port, for each VPC security group attached to the
    # instance: [{ id:, sources: [...], group_refs: [...] }]. A rule counts when it allows all
    # traffic or TCP on a port range that includes the instance's port; rules for other ports
    # can't reach the database. sources are IPv4 CIDRs, IPv6 CIDRs and prefix-list IDs;
    # group_refs are security groups the rules allow by reference.
    def security_group_ingress
      db_port = port.to_i
      ids = (aws_attr('VpcSecurityGroups') || []).map { |g| g['VpcSecurityGroupId'] }.compact
      ids.map do |id|
        perms = aws_json(%W(ec2 describe-security-groups --group-ids #{id} --query SecurityGroups[0].IpPermissions)) || []
        reaching = perms.select { |p| reaches_port?(p, db_port) }
        sources = reaching.flat_map do |p|
          (p['IpRanges'] || []).map { |r| r['CidrIp'] } +
            (p['Ipv6Ranges'] || []).map { |r| r['CidrIpv6'] } +
            (p['PrefixListIds'] || []).map { |r| r['PrefixListId'] }
        end
        group_refs = reaching.flat_map { |p| (p['UserIdGroupPairs'] || []).map { |g| g['GroupId'] } }
        { id: id, sources: sources.compact.uniq, group_refs: group_refs.compact.uniq }
      end
    end

    # CloudWatch alarms on this instance's FreeStorageSpace metric.
    def free_storage_alarms
      return [] unless aws_available?

      aws_json(%W[cloudwatch describe-alarms-for-metric --namespace AWS/RDS --metric-name FreeStorageSpace
                  --dimensions Name=DBInstanceIdentifier,Value=#{@aws_instance_id} --query MetricAlarms]) || []
    end

    # Pending maintenance actions for this instance (filtered server-side; the
    # response's ResourceIdentifier is the ARN, not the bare identifier).
    def pending_maintenance_actions
      return [] unless aws_available?

      aws_json(%W[rds describe-pending-maintenance-actions --filters Name=db-instance-id,Values=#{@aws_instance_id}
                  --query PendingMaintenanceActions]) || []
    end

    # Who manages a KMS key: "CUSTOMER" for a customer-managed key, "AWS" for an
    # AWS-managed one such as aws/rds. Looked up once per key per scan (errors too);
    # raises on failure, e.g. without kms:DescribeKey permission.
    def kms_key_manager(key_id)
      key = [key_id, @region, @profile]
      cache = AwsRdsConnection.kms_cache
      cache[key] ||= begin
        { data: aws_json(%W[kms describe-key --key-id #{key_id} --query KeyMetadata.KeyManager]) }
      rescue AwsRdsConnectionError => e
        { error: e.message }
      end
      raise AwsRdsConnectionError, cache[key][:error] if cache[key][:error]

      cache[key][:data]
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

    # Whether a security-group ingress rule (one IpPermissions entry) admits traffic to db_port:
    # protocol -1 means all traffic; otherwise it must be TCP with db_port in FromPort..ToPort.
    def reaches_port?(perm, db_port)
      protocol = perm['IpProtocol'].to_s
      return true if protocol == '-1'
      return false unless %w[tcp 6].include?(protocol)

      perm['FromPort'].to_i <= db_port && db_port <= perm['ToPort'].to_i
    end

    def describe_instance
      key = [@aws_instance_id, @region, @profile]
      cache = AwsRdsConnection.instance_cache
      cache[key] ||= fetch_instance
      raise AwsRdsConnectionError, cache[key][:error] if cache[key][:error]

      cache[key][:data]
    end

    def fetch_instance
      data = aws_json(%W(rds describe-db-instances --db-instance-identifier #{@aws_instance_id} --query DBInstances[0]))
      return { error: "Preflight failed: no RDS instance data returned for #{@aws_instance_id}" } unless data.is_a?(Hash)

      { data: data }
    rescue AwsRdsConnectionError => e
      { error: "Preflight failed: #{e.message}" }
    end

    # Runs `aws <args...> --output json` with the configured region/profile, every
    # argument shell-escaped. Returns parsed JSON; raises on a non-zero exit or
    # unparseable output.
    def aws_json(args)
      args += ['--region', @region] unless @region.empty?
      args += ['--profile', @profile] unless @profile.empty?
      args += ['--output', 'json']
      cmd = (['aws'] + args).map { |a| Shellwords.escape(a) }.join(' ')
      result = inspec.command(cmd)
      unless result.exit_status.zero?
        raise AwsRdsConnectionError, "`aws #{args[0, 2].join(' ')}` exited #{result.exit_status}: #{result.stderr.strip}"
      end

      JSON.parse(result.stdout)
    rescue JSON::ParserError => e
      raise AwsRdsConnectionError, "could not parse `aws #{args[0, 2].join(' ')}` output: #{e.message}"
    end
  end
end
