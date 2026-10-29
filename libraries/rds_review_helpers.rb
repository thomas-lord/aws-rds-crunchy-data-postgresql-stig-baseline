# A control whose automated checks are followed by a step only a person can do must not
# read as Passed just because the automated part passed. These controls evaluate their
# checks up front with rds_check, and report through rds_review_results:
#
#   rds_review_results(checks, manual_note).each do |result|
#     describe(result[:title]) { instance_exec(&result[:report]) }
#   end
#
# (The describe stays in the control because `inspec check` counts only the describe
# blocks it can see there. Each result carries its own report block because the control
# can't name this module: InSpec loads libraries in its own namespace.) With every check passing, that is a single skipped result,
# so the control shows as Not Reviewed, listing what each check found and the manual
# step. With any check failing, each check is reported pass or fail and the manual step
# is listed too, so the control shows as Failed. Without a manual note, checks are just
# reported pass or fail.
module RdsReviewHelpers
  # One automated check, run now. The block returns [passed, found], where found is what
  # the check saw, for the report. An error, such as a failed AWS call, fails the check
  # with its message.
  def rds_check(title)
    passed, found = yield
    { title: title, passed: passed ? true : false, found: found.to_s }
  rescue StandardError => e
    { title: title, passed: false, found: e.message }
  end

  # The parameter-group apply status as an rds_check, or nil without AWS discovery.
  def rds_apply_status_check(conn)
    return nil unless conn.aws_available?

    rds_check('RDS DB parameter group apply status') do
      status = conn.parameter_apply_status
      [status.to_s != 'pending-reboot', status || 'unknown']
    end
  end

  # SHOW <setting> compared the way InSpec's cmp compares strings: ignoring case and
  # surrounding whitespace.
  def rds_setting_check(conn, sql, setting, expected)
    rds_check("#{setting} (expected #{expected})") do
      value = sql.query("SHOW #{setting};", [conn.db]).output.strip
      [value.casecmp?(expected.to_s.strip), value.empty? ? '(no output)' : value]
    end
  end

  # What an approval-list check found, e.g. "a (db1), b (db2); not approved: b (db2)".
  def rds_approval_summary(found, unapproved)
    return 'none' if found.empty?
    return found.join(', ') if unapproved.empty?

    "#{found.join(', ')}; not approved: #{unapproved.join(', ')}"
  end

  # Joins the manual notes that apply, or nil when none does.
  def rds_manual_note(*notes)
    notes = notes.compact
    notes.empty? ? nil : notes.join(' ')
  end

  def rds_review_results(checks, manual_note)
    checks = checks.compact
    failed = checks.reject { |check| check[:passed] }
    if manual_note && failed.empty?
      summary = checks.map { |check| "#{check[:title]}: #{check[:found]}" }.join('; ')
      message = "Not reviewed. Automated checks passed (#{summary}). Manual review required: #{manual_note}"
      return [{ title: message, status: :skipped, message: message }].map { |result| result.merge(report: RdsReviewHelpers.report_block(result)) }
    end

    results = checks.map do |check|
      { title: "#{check[:title]}: #{check[:found]}", status: check[:passed] ? :passed : :failed,
        message: "#{check[:title]} failed; found: #{check[:found]}" }
    end
    results << { title: "Manual review required: #{manual_note}", status: :skipped, message: manual_note } if manual_note
    results.map { |result| result.merge(report: RdsReviewHelpers.report_block(result)) }
  end

  # The body of the describe block for one result, run there with instance_exec.
  def self.report_block(result)
    message = result[:message]
    case result[:status]
    when :skipped then proc { skip message }
    when :failed then proc { it('should pass') { ::RSpec::Expectations.fail_with(message) } }
    else proc { it('should pass') { nil } }
    end
  end
end

# The leading :: is required: InSpec evaluates library files inside its own context,
# where a bare `Inspec` doesn't resolve to the top-level module.
::Inspec::Rule.include(RdsReviewHelpers) # rubocop:disable Style/RedundantConstantBase
