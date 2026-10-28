# Control-body helpers shared across this profile's controls.
#
# InSpec evaluates each control block on an Inspec::Rule instance, so these are
# mixed into Inspec::Rule; inside them `input`, `describe`, `only_if`, and
# resources behave exactly as they would written inline in a control.
module RdsStigHelpers
  # The profile's aws_rds_connection, built from the standard connection inputs.
  def rds_connection
    aws_rds_connection(
      aws_instance_id: input('aws_db_instance_identifier'),
      region: input('aws_region'),
      profile: input('aws_cli_profile'),
      host: input('pg_host'),
      port: input('pg_port'),
      db: input('pg_db'),
      dba: input('pg_dba')
    )
  end

  # Skips the calling control unless AWS CLI discovery is in use. Once it is, AWS
  # call failures fail the control (see aws_rds_connection) rather than skip it.
  def rds_only_if_aws(conn)
    only_if('The AWS CLI must be installed and the aws_db_instance_identifier input set to evaluate this control.') do
      conn.aws_available?
    end
  end

  # Flags parameter-group changes not yet applied to the running instance, so a
  # live SHOW value is never mistaken for the configured one. No-op without AWS.
  def rds_check_parameter_apply_status(conn)
    return unless conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end

  PGAUDIT_LOG_CLASSES = %w(read write function role ddl misc misc_set).freeze

  # The classes a pgaudit.log value turns on, read the way pgaudit reads it: comma-separated,
  # case-insensitive, left to right, where 'all' adds every class, 'none' adds nothing, and a
  # leading '-' removes a class (so 'all, -misc' is everything but misc). Returns
  # [enabled_classes, unknown_tokens]; unknown tokens include psql error text.
  def self.pgaudit_log_classes(value)
    enabled = []
    unknown = []
    value.to_s.split(',').map { |t| t.strip.downcase }.reject(&:empty?).each do |token|
      remove = token.start_with?('-')
      name = remove ? token[1..-1].strip : token
      classes =
        case name
        when 'all' then PGAUDIT_LOG_CLASSES
        when 'none' then []
        when *PGAUDIT_LOG_CLASSES then [name]
        else
          unknown << token
          next
        end
      enabled = remove ? enabled - classes : enabled | classes
    end
    [enabled, unknown]
  end

  # Checks that pgaudit.log turns on every class in the pgaudit_log_items input. Callers
  # must also have a describe written in the control itself (see inspec check note below).
  def rds_check_pgaudit_log(conn, sql)
    value = sql.query('SHOW pgaudit.log;', [conn.db]).output.strip
    enabled, unknown = RdsStigHelpers.pgaudit_log_classes(value)
    # The input goes through the same parser, so it can say e.g. ['all', '-misc']. A misspelled
    # class in it is kept, and fails below because no setting can enable it.
    required, misspelled = RdsStigHelpers.pgaudit_log_classes(input('pgaudit_log_items').join(','))

    describe "pgaudit.log setting (#{value})" do
      it 'should contain only pgaudit class names' do
        expect(unknown).to be_empty
      end
      (required + misspelled).each do |log_class|
        it "should enable the #{log_class} class" do
          expect(enabled).to include(log_class)
        end
      end
    end
  end

  # PPSM exposure check on each of the instance's VPC security groups (V-261889,
  # V-261926), given conn.security_group_ingress: no 0.0.0.0/0 ingress, and only
  # CIDRs listed in pg_approved_ingress_cidrs. Callers must also assert the group
  # list is non-empty, in a describe written in the control itself (`inspec
  # check` only counts describe blocks it can see in the control's source).
  def rds_check_security_group_ingress(groups)
    approved_cidrs = input('pg_approved_ingress_cidrs')

    groups.each do |group|
      cidrs = group[:cidrs]
      describe "Security group #{group[:id]} ingress CIDRs (#{cidrs.join(', ')})" do
        it 'should not include the public 0.0.0.0/0 range' do
          expect(cidrs).not_to include('0.0.0.0/0')
        end
        it 'should only include CIDRs approved via the pg_approved_ingress_cidrs input (PPSM CAL / vulnerability assessment)' do
          expect(cidrs - approved_cidrs).to be_empty
        end
      end
    end
  end
end

::Inspec::Rule.include(RdsStigHelpers)
