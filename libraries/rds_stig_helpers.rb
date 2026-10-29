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
      dba: input('pg_dba_user'),
      use_manual_endpoint: input('pg_use_manual_endpoint')
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

  # Checks a setting RDS hides from logins without rds_superuser, such as rds.force_ssl:
  # SHOW reports it as unrecognized. With AWS discovery the value comes from the instance's
  # parameter group (pair this with rds_check_parameter_apply_status); without it, SHOW is
  # tried, and a hidden setting becomes a manual-review skip.
  def rds_check_hidden_parameter(conn, sql, name, expected)
    if conn.aws_available?
      describe "RDS DB parameter group setting #{name}" do
        subject { conn.db_parameter(name) }
        it { should cmp expected }
      end
      return
    end

    result = sql.query("SHOW #{name};", [conn.db])
    if result.output.include?('unrecognized configuration parameter')
      manual_note = "#{name} is hidden from #{conn.dba}, which lacks rds_superuser, and AWS CLI discovery is off; manually verify it is #{expected} in the instance's DB parameter group."
      describe manual_note do
        skip manual_note
      end
      return
    end

    describe result do
      its('output.strip') { should cmp expected }
    end
  end

  # Databases the per-database checks visit: every one that accepts connections except
  # rdsadmin, AWS's own, which customers can't connect to. template1 is included because new
  # databases copy its objects.
  DATABASES_SQL = "SELECT datname FROM pg_database WHERE datallowconn AND datname <> 'rdsadmin' ORDER BY 1;".freeze

  # Runs query in every database (see DATABASES_SQL) and returns [rows, unreadable]: rows
  # holds a [database, row] pair for each output row matching row_pattern, and unreadable
  # names each database (or the database list) whose output had anything else, such as a
  # connection or permission error. Objects such as extensions and functions are per
  # database, so checking only pg_db would miss the others.
  def rds_query_each_database(conn, sql, query, row_pattern)
    databases = sql.query(DATABASES_SQL, [conn.db]).lines
    return [[], ['(list of databases)']] if databases.empty? || databases.any? { |d| d =~ /\A(psql:|ERROR:|FATAL:)/i }

    rows = []
    unreadable = []
    databases.each do |database|
      lines = sql.query(query, [database]).lines
      if lines.all? { |line| line =~ row_pattern }
        rows.concat(lines.map { |line| [database, line] })
      else
        unreadable << database
      end
    end
    [rows, unreadable]
  end

  # Disk-level encryption at rest (V-261901, V-261930, V-261931). On RDS this is storage
  # encryption with a KMS key, which covers the data volume, automated backups, snapshots
  # and read replicas. With pg_require_customer_managed_kms_key set, the key must also be
  # customer-managed rather than AWS-managed (aws/rds). Without AWS discovery this is a
  # manual-review skip.
  def rds_check_storage_encryption(conn)
    unless conn.aws_available?
      manual_note = 'RDS storage encryption at rest cannot be checked without AWS CLI discovery (aws_db_instance_identifier + aws CLI); manually verify "Encryption: Enabled" with a KMS key on the instance\'s Configuration tab in the RDS console.'
      describe manual_note do
        skip manual_note
      end
      return
    end

    key_id = conn.aws_instance_attr('KmsKeyId')
    describe "RDS storage encryption at rest (KmsKeyId: #{key_id || 'none'})" do
      subject { conn.aws_instance_attr('StorageEncrypted') }
      it { should cmp true }
    end

    return unless input('pg_require_customer_managed_kms_key')

    describe "KMS key manager for RDS storage encryption (#{key_id || 'no key'}); CUSTOMER is customer-managed, AWS is AWS-managed" do
      subject { key_id && conn.kms_key_manager(key_id) }
      it { should cmp 'CUSTOMER' }
    end
  end

  PGAUDIT_LOG_CLASSES = %w[read write function role ddl misc misc_set].freeze

  # The classes a pgaudit.log value turns on, read the way pgaudit reads it: comma-separated,
  # case-insensitive, left to right, where 'all' adds every class, 'none' adds nothing, and a
  # leading '-' removes a class (so 'all, -misc' is everything but misc). Returns
  # [enabled_classes, unknown_tokens]; unknown tokens include psql error text.
  def self.pgaudit_log_classes(value)
    enabled = []
    unknown = []
    value.to_s.split(',').map { |t| t.strip.downcase }.reject(&:empty?).each do |token|
      remove = token.start_with?('-')
      name = remove ? token[1..].strip : token
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
  # V-261926), given conn.security_group_ingress: no 0.0.0.0/0 or ::/0 ingress, and
  # only sources listed in pg_approved_ingress_cidrs. Callers must also assert the group
  # list is non-empty, in a describe written in the control itself (`inspec
  # check` only counts describe blocks it can see in the control's source).
  #
  # Only rules that reach the database port count (see security_group_ingress). Sources are
  # IPv4/IPv6 CIDRs and prefix-list IDs; rules allowing another security group by reference
  # are listed in the title but not failed, since they admit only that group's members.
  def rds_check_security_group_ingress(groups)
    approved_sources = input('pg_approved_ingress_cidrs')

    groups.each do |group|
      sources = group[:sources]
      listed = sources + group[:group_refs].map { |ref| "#{ref} (security group)" }
      describe "Security group #{group[:id]} ingress to the database port (#{listed.empty? ? 'none' : listed.join(', ')})" do
        it 'should not be open to the internet (0.0.0.0/0 or ::/0)' do
          expect(sources & %w[0.0.0.0/0 ::/0]).to be_empty
        end
        it 'should only include CIDRs and prefix lists approved via the pg_approved_ingress_cidrs input (PPSM CAL / vulnerability assessment)' do
          expect(sources - approved_sources).to be_empty
        end
      end
    end
  end
end

# The leading :: is required: InSpec evaluates library files inside its own context,
# where a bare `Inspec` doesn't resolve to the top-level module.
::Inspec::Rule.include(RdsStigHelpers) # rubocop:disable Style/RedundantConstantBase
