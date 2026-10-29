control 'V-261936' do
  title 'Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc <<~EOT
    Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

    Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

    This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

    The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).
  EOT
  desc 'check', <<~EOT
    If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:

    To list the version of installed PostgreSQL using psql:

    $ sudo su - postgres
    $ psql --version

    To list the current version of software for RPM:

    $ rpm -qa | grep postgres

    To list the current version of software for APT:

    $ apt-cache policy postgres

    All versions of PostgreSQL are listed here: http://www.postgresql.org/support/versioning/.

    All security-relevant software updates for PostgreSQL are listed here: http://www.postgresql.org/support/security/.

    If PostgreSQL is not at the latest version, this is a finding.

    If PostgreSQL is not at the latest version and the evaluated version has CVEs (IAVAs), then this is a CAT I finding.
  EOT
  desc 'fix', <<~EOT
    Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag gid: 'V-261936'
  tag rid: 'SV-261936r1137667_rule'
  tag stig_id: 'CD16-00-009200'
  tag cci: ["CCI-002605"]
  tag nist: ["SI-2 c"]
  conn = rds_connection
  rds_only_if_aws(conn)

  # The STIG: "If PostgreSQL is not at the latest version, this is a finding." On RDS the
  # latest is the newest minor version RDS offers for the running major version. With
  # automatic minor version upgrades on, RDS moves the instance forward on its own in the
  # maintenance window, so that also passes. RDS only upgrades automatically to the version
  # AWS marks as the automatic-upgrade target, which can lag the newest release; the result
  # says so.
  checks = [
    rds_check('RDS engine minor version (the latest RDS offers, or automatic minor version upgrades on)') do
      version = conn.aws_instance_attr('EngineVersion')
      newer = conn.newer_minor_versions
      auto_upgrade = conn.aws_instance_attr('AutoMinorVersionUpgrade') == true
      found =
        if newer.empty?
          "#{version}, the latest"
        elsif auto_upgrade
          "#{version}, newer available: #{newer.join(', ')}. AutoMinorVersionUpgrade is on, so RDS upgrades the instance " \
            "during its maintenance window (#{conn.aws_instance_attr('PreferredMaintenanceWindow')}) once AWS makes a newer " \
            'version the automatic-upgrade target'
        else
          "#{version}, newer available: #{newer.join(', ')}. AutoMinorVersionUpgrade is off"
        end
      [newer.empty? || auto_upgrade, found]
    end,
    rds_check('RDS pending maintenance actions') do
      actions = conn.pending_maintenance_actions.flat_map { |resource| (resource['PendingMaintenanceActionDetails'] || []).map { |detail| detail['Action'] } }
      [actions.empty?, actions.empty? ? 'none' : actions.join(', ')]
    end
  ]
  rds_review_results(checks, nil).each do |result|
    describe(result[:title]) { instance_exec(&result[:report]) }
  end
end
